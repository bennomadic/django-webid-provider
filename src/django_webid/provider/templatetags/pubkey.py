from django import template

register = template.Library()

#XXX this can be made smarter, but...
DEPRECATED_PUBKEY_SNIPPET = u"""
<div about="#cert" typeof="rsa:RSAPublicKey">
  <div href="%(uri)s" rel="cert:identity"></div>
  <div property="rsa:modulus" datatype="cert:hex" content="%(mod)s">%(pretty_mod)s</div>
  <div property="rsa:public_exponent" datatype="cert:int" content="%(exp)s">%(exp)s</div>
  <div about="%(uri)s"></div>
</div>
"""

#XXX :( I was liking the %(pretty_mod)s...

PUBKEY_SNIPPET_RDFA = u"""
<div rel="cert:key">
    <p>One of my Public Keys... made on...</p>
    <div typeof="cert:RSAPublicKey">
      <dl>
      <dt>Modulus (hexadecimal)</dt>
      <dd style="word-wrap: break-word; white-space: pre-wrap;"
         property="cert:modulus" datatype="xsd:hexBinary">%(mod)s</dd>
      <dt>Exponent (decimal)</dt>
      <dd property="cert:exponent" datatype="xsd:integer">%(exp)s</dd>
      </dl>
    </div>
</div>
"""
PUBKEY_SNIPPET_RDFXML = u"""
    <cert:key>
      <cert:RSAPublicKey>
        <rdfs:label>made on [...] on my laptop</rdfs:label>
        <cert:modulus rdf:datatype="http://www.w3.org/2001/XMLSchema#hexBinary">
        %(mod)s
        </cert:modulus>
        <cert:exponent rdf:datatype="http://www.w3.org/2001/XMLSchema#integer">%(exp)s</cert:exponent>
      </cert:RSAPublicKey>
    </cert:key>"""

PUBKEY_SNIPPET_TURTLE = u"""
  :key [ a :RSAPublicKey;
    rdfs:label "key made on [...] on my laptop";
    :modulus
   "%(mod)s"^^xsd:hexBinary;
    :exponent %(exp)s ;
  ] .
"""

PADDING_CHR = u'\u271c'
PADDING_SPACES =  u' %s ' % PADDING_CHR
TRAILING_CHR = u'\u2665'

def prettyfy(hexstr):
    return PADDING_SPACES.join([
        hexstr[x:x+2].upper()
        for x in xrange(0,len(hexstr),2)
        ]) + ' %s' % TRAILING_CHR

def do_pubkey_rdf(parser, token):
    try:
        tag_name, _format, user_var = token.split_contents()
    except ValueError:
        raise template.TemplateSyntaxError("%r tag requires a single argument" % token.contents.split()[0])
    if not (_format[0] == _format[-1] and _format[0] in ('"', "'")):
        raise template.TemplateSyntaxError("%r tag's argument should be in quotes" % tag_name)
    return_format = _format[1:-1]
    if not return_format in ('rdfa', 'rdfxml', 'turtle'):
        raise template.TemplateSyntaxError("%r tag format argument should be one of the following: 'rdfa', 'rdfxml'" % tag_name)
    return PubKeyRDFNode(return_format, user_var)


class PubKeyRDFNode(template.Node):
    def __init__(self, _format, user_var):
        self._format = _format
        self.user_var = template.Variable(user_var)
    def render(self, context):
        try:
            #XXX REFACTOR
            uu = self.user_var.resolve(context)
            if self._format == "rdfa":
                r = ""
                for pk in uu.keys:
                    r = r + PUBKEY_SNIPPET_RDFA % {'mod':pk.mod,
                        'pretty_mod': prettyfy(pk.mod),
                        'exp':pk.exp,
                        'uri': uu.absolute_webid_uri,
                        }
                return r
            if self._format == "turtle":
                r = ""
                for pk in uu.keys:
                    r = r + PUBKEY_SNIPPET_TURTLE % {'mod':pk.mod,
                        'exp':pk.exp,
                        }
                return r
            if self._format == "rdfxml":
                r = ""
                for pk in uu.keys:
                    r = r + PUBKEY_SNIPPET_RDFXML % {'mod':pk.mod,
                        'exp':pk.exp,
                        }
                return r
            raise template.TemplateSyntaxError("format should be one of the following: 'rdfa', 'rdfxml'")
        except template.VariableDoesNotExist:
            return ''

register.tag('pubkey_rdf', do_pubkey_rdf)
