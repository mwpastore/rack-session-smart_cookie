# Rack::Session::SmartCookie

The version of Rack::Session::Cookie that ships with Rack has the following
limitations:

* Insecure SHA1 (HMAC-SHA1) by default
* Slow and/or bloated JSON, ZipJSON, or Marshal encoding out of the box
* JSON encodings do not preserve Symbols
* Digest is double-encoded and bloated (hexdigest of a base64)
* Base64-encoded strings contain unecessary padding and characters that need to
  be escaped (e.g. `/` becomes `%2F`), wasting precious cookie bytes
* It has some bugs in the size check that may lead to truncated cookies, token
  leakage, and/or cross-site request forgery

Of course, none of these are true show-stoppers, and the worst can be worked
around by passing e.g. `:hmac` and `:coder` to the initializer. But we are nice
people, and we deserve nice things. This gem provides a minor derivative of
Rack::Session::Cookie with the following improvements:

* Secure SHA2 (HMAC-SHA-256) by default
* Compact binary serialization format (currently [MessagePack][3] but will
  likely change to [CBOR][4] in the future) out of the box
* Symbols are preserved with the default `:coder`
* Digest is single-encoded and compact (base64 of a digest)
* Base64-encoded strings are not padded and conform to URL-encoded form data
  (e.g. `/` becomes `_`)
* It does not perform a size check (use [Rack::Protection::MaximumCookie][2]
  if you care about cookie limits)

The resultant cookies values with a small-to-medium sized session can be up to
30% smaller in an apples-to-apples comparison (see below for examples).

### Strategy

The main distinguishing feature of this cf. the stock implementation is that
the encoding (and decoding) step has been separated into two stages: 1. binary
serialization and 2. stringification, instead of being combined into a single
"coder" class. This allows the various cookie components to be either both
serialized and stringified (in the case of the session payload) or merely
stringified (in the case of the digest).

The other key realization is that the method Rack uses to escape cookie data
([URI.encode_www_form_component][5]) will only ever allow URL-safe Base64 plus
period (`.`) and asterisk (`*`), so there's no sense in using any
stringification scheme other than URL-safe Base64! It doesn't need to be
configurable. The serializer remains configurable as the `:coder`.

The remaining differences are mostly just better defaults: MessagePack and
SHA2.

### Other Features

* Calling `#destroy` on the session deletes the cookie (by sending a Set-Cookie
  header that immediately expires it) instead of generating an empty session

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rack-session-smart_cookie'
```

And then execute:

```console
$ bundle
```

Or install it yourself as:

```console
$ gem install rack-session-smart_cookie
```

## Usage

```ruby
use Rack::Session::SmartCookie
```

Rack::Session::SmartCookie accepts the same options as
[Rack::Session::Cookie][6]. If you choose to override the default `:coder`, it
should *not* perform the Base64 steps.

You can easily register additional custom types on the default coder's factory:

```ruby
my_coder = Rack::Session::SmartCookie::MessagePack.new
my_coder.factory.register_type(0x00, MyCustomType) # 0x60..0xFF are reserved

use Rack::Session::SmartCookie, :coder=>my_coder
```

## Comparisons

For general size and performance benchmarks of the encoding schemes, see
[here][1]. Unfortunately, the post is slightly out-of-date and doesn't include
ZipJSON (Zlib+JSON) results. However, I was able to run the benchmarks locally
and add ZipJSON. Although it comes in second-most compact at 289 bytes (cf.
protocol buffers and MessagePack at 204 and 373 bytes, respectively), it was
97% slower to encode and 91% slower to decode cf. MessagePack.

I put this mock session payload through the following configurations with SHA2
and 128 sidbits and here are the results:

```ruby
{
  :user_id=>514,
  :roles=>[:user, :moderator, :mailbox],
  :data=>'{"foo":"bar","qux":21}',
  :issued_at=>Time.now.to_f,
  :valid_for=>30*24*3_600
}
```

### Rack::Session::Cookie w/ Base64::Marshal

```
BAh7C0kiD3Nlc3Npb25faWQGOgZFVEkiRTg3MzJkMTEzNDQyZjQyM2FlZGUy%0AMTdmNDY0OWEyOTk5
MjkyYzg2M2JkNTFlY2VjYjY2ZDAzMTg0MTYzZWE3YTcG%0AOwBGSSIMdXNlcl9pZAY7AEZpAgICSSIK
cm9sZXMGOwBGWwg6CXVzZXI6Dm1v%0AZGVyYXRvcjoMbWFpbGJveEkiCWRhdGEGOwBGSSIbeyJmb28i
OiJiYXIiLCJx%0AdXgiOjIxfQY7AFRJIg5pc3N1ZWRfYXQGOwBGZhYxNTA5MjAzMDIzLjI3MzE2%0AN
UkiDnZhbGlkX2ZvcgY7AEZpAwCNJw%3D%3D%0A--15aebb42ba0ff0a28436556c64eb2ef6d4dc7c6
a39e164eac0889052cec4f83f
```

Size: 420 bytes (100%)

Note the percent-encoded characters and hex-encoded digest here and in the
other Rack::Session::Cookie results.

### Rack::Session::Cookie w/ Base64::JSON

```
eyJzZXNzaW9uX2lkIjoiMTA4YzM1ZGIxMTFkNWZlMjk5NzUwMTc1Mzc2MzVm%0AMDJlZTIxMjM4ZmIx
OTg2NDQ0ZTc4MTliY2RjZGQyYjc2YSIsInVzZXJfaWQi%0AOjUxNCwicm9sZXMiOlsidXNlciIsIm1v
ZGVyYXRvciIsIm1haWxib3giXSwi%0AZGF0YSI6IntcImZvb1wiOlwiYmFyXCIsXCJxdXhcIjoyMX0i
LCJpc3N1ZWRf%0AYXQiOjE1MDkyMDI5NzEuODk3MzUyLCJ2YWxpZF9mb3IiOjI1OTIwMDB9%0A--7a6
000bdece71118e768ccffedc645ace865b829536e335c304c00bb9050c625
```

Size: 377 bytes (90%)

### Rack::Session::Cookie w/ Base64::ZipJSON

```
eJwdjeGKwyAQhN9lf8uxGrcaX%2BU8wqa7gpCeXEyOQum7V%2FJvZj5m5gVde6%2Ft%0Ad6kCCcok1h
bvwnqfJLpJ2VkpIXrxSmQZ76uzBb0qzYokSPY2E8aAXDQSg4Gz%0A636NkfUG9rZph%2FR9xYM%2Bmu
jOR7s0121tT%2FgxIHzwuH9lKK1lSBlW3jOYDH%2Fn%0Ac3hn36NQez9VFj4gWcLZoZsxfN1ioCkY%2
BOetylLGdHI0IOL7A%2BnjQaI%3D%0A--fc193337b2900b6ce893143b5a52d36b55fafebc21cbde
83712dce56bbf836f4
```

Size: 334 bytes (80%)

### Rack::Session::SmartCookie w/ MessagePack

```
hqpzZXNzaW9uX2lk2UBiMGEzYzhlZTE4NzY3YjcwOTNmNThhN2E4MTI4NTNmNTlmNDYwOTgwMDA5NGY
1Y2E4MTg5MjFjMjA4ZWQ1ZDY3p3VzZXJfaWTNAgKlcm9sZXOT1gB1c2VyxwkAbW9kZXJhdG9yxwcAbW
FpbGJveKRkYXRhtnsiZm9vIjoiYmFyIiwicXV4IjoyMX2paXNzdWVkX2F0y0HWfSbUfbp0qXZhbGlkX
2Zvcs4AJ40A.CRGTAgpN19Iz1plyX14kHmQYWTe0OtFbetqKZmCvSfg
```

Size: 292 bytes (70%)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/mwpastore/rack-session-smart_cookie.

## License

The gem is available as open source under the terms of the [MIT
License](http://opensource.org/licenses/MIT).

[1]: https://gist.github.com/eirc/1300627
[2]: https://github.com/mwpastore/rack-protection-maximum_cookie
[3]: https://msgpack.org
[4]: http://cbor.io
[5]: https://ruby-doc.org/stdlib-2.4.2/libdoc/uri/rdoc/URI.html#method-c-encode_www_form_component
[6]: http://www.rubydoc.info/gems/rack/Rack/Session/Cookie
