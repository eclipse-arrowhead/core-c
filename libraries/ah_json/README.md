    @dir ah_json @brief JSON library.

JSON, or JavaScript Object Notation, is a human-readable and open data
interchange format. It was popularized partly because of its simplicity and
partly because of its adoption by the prevailing World Wide Web browser
JavaScript engines, which made it highly accessible to web applications. The
JSON format is commonly used to encode payloads part of HTTP messages
(see include/ah/http.h) in the context of web services. Because of its
popularity on the web, it has become an important interchange format in the
Arrowhead ecosystem.

Being designed with human-readability as a primary goal, JSON is tricky to parse
efficiently on resource-constrained systems. For example, it cannot be reliably
determined how much memory must be allocated to represent any specific JSON
value before it is read and analyzed in full. As the Arrowhead Core C libraries
also target resource-constrained devices, this particular JSON library makes
some important sacrifices to improve performance and reduce its memory
footprint. Firstly, it primarily handles reading, or parsing JSON data. You are
assumed to be able to produce JSON data on your own, perhaps through clever use
of sprintf() statements. Secondly, the output representation produced when
parsing JSON only indirectly forms a tree, which is what every JSON object and
array actually describes. More specifically, parsing produces a list of tokens,
each of which indicates its type, how many child values it has or how long it
is, as well as its tree depth. You must write your own routines for converting
JSON representations into instances of C data structures.
