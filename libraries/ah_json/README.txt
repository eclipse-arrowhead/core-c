/** @dir

Arrowhead Core JSON library.

JSON, or JavaScript Object Notation, is a human-readable and open data
interchange format. It was popularized partly because of its simplicity in
comparison to XML, which was the format it supplanted for information exchange
use cases, and partly because of its adoption by the prevailing World Wide Web
browser JavaScript engines, which made it highly accessible for web
applications. The JSON format is commonly used to encode payloads part of HTTP
messages (see include/ah/http.h) in the context of web services, and has become
an important interchange format in the Arrowhead ecosystem.

Being designed with human-readability as a primary goal, JSON is tricky to parse
efficiently on resource-constrained systems. For example, it cannot be reliably
determined how much memory must be allocated to represent any specific JSON
value before it is read and analyzed in full. As the Arrowhead Core C libraries
also target resource-constrained devices, this particular JSON library makes
some important sacrifices to improve performance and reduce its memory
footprint. Firstly, it only handles reading, or parsing JSON data. You are
assumed to be able to produce JSON data on your own, perhaps through clever use
of sprintf() statements. Secondly, the library is only loosely conformant to the
ECMA-404 standard, which standardizes the JSON format. The library is guaranteed
to successfully parse any valid JSON input, but it may also succeed in parsing
certain invalid inputs. Thirdly, the output representation produced when parsing
JSON only indirectly forms a tree, which is what every JSON object and array
actually describes. More specifically, parsing produces a list of tokens, each
of which indicates its type, how many child nodes it has or how long it is, as
well as its tree depth.

*/