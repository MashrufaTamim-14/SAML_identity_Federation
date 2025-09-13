from flask import Flask, request, render_template, redirect, session
import base64, uuid, datetime
from lxml import etree

app = Flask(__name__)
app.secret_key = "idp-dev-secret-very-secret"

IDP_ENTITY = "http://idp1.example.com:5000"

def build_saml_response(username, in_response_to, acs_url, audience):
    """Return an XML Element (Response)"""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    resp = etree.Element("Response", attrib={
        "ID": "_" + uuid.uuid4().hex,
        "Version": "2.0",
        "IssueInstant": now,
        "InResponseTo": in_response_to,
        "Destination": acs_url
    })
    issuer = etree.SubElement(resp, "Issuer")
    issuer.text = IDP_ENTITY

    status = etree.SubElement(resp, "Status")
    status_code = etree.SubElement(status, "StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")

    assertion = etree.SubElement(resp, "Assertion", ID="_" + uuid.uuid4().hex, IssueInstant=now, Version="2.0")
    a_issuer = etree.SubElement(assertion, "Issuer")
    a_issuer.text = IDP_ENTITY

    subj = etree.SubElement(assertion, "Subject")
    nameid = etree.SubElement(subj, "NameID")
    nameid.text = username

    subj_conf = etree.SubElement(subj, "SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(subj_conf, "SubjectConfirmationData", NotOnOrAfter=now, Recipient=acs_url, InResponseTo=in_response_to)

    cond = etree.SubElement(assertion, "Conditions", NotBefore=now, NotOnOrAfter=now)
    aud_restr = etree.SubElement(cond, "AudienceRestriction")
    aud = etree.SubElement(aud_restr, "Audience")
    aud.text = audience

    authn = etree.SubElement(assertion, "AuthnStatement", AuthnInstant=now)
    authn_ctx = etree.SubElement(authn, "AuthnContext")
    etree.SubElement(authn_ctx, "AuthnContextClassRef").text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    return resp

@app.route("/sso", methods=["GET"])
def sso():
    """
    Expect query params:
      saml_request = base64-encoded XML AuthnRequest
      relay = optional relay state
    """
    saml_req_b64 = request.args.get("saml_request")
    relay = request.args.get("relay", "")
    if not saml_req_b64:
        return "Missing saml_request", 400

    try:
        xml = base64.b64decode(saml_req_b64).decode("utf-8")
        doc = etree.fromstring(xml.encode("utf-8"))
    except Exception as e:
        return f"Bad AuthnRequest: {e}", 400

    # extract info
    authn_id = doc.get("ID")
    acs = doc.get("AssertionConsumerServiceURL")
    issuer_el = doc.find(".//Issuer")
    sp_issuer = issuer_el.text if issuer_el is not None else ""

    # If user already logged into IdP -> auto-post SAMLResponse (SSO)
    if session.get("user"):
        username = session["user"]
        resp_xml = build_saml_response(username, in_response_to=authn_id, acs_url=acs, audience=sp_issuer)
        resp_b64 = base64.b64encode(etree.tostring(resp_xml)).decode("utf-8")
        return render_template("saml_post_form.html", acs_url=acs, saml_response=resp_b64, relay=relay)

    # Otherwise show login form; include hidden fields to preserve context
    return render_template("login.html", acs=acs, in_response_to=authn_id, sp_issuer=sp_issuer, relay=relay)

@app.route("/do_login", methods=["POST"])
def do_login():
    username = request.form.get("username", "user@example.com")
    acs = request.form.get("acs")
    in_response_to = request.form.get("in_response_to")
    sp_issuer = request.form.get("sp_issuer")
    relay = request.form.get("relay", "")

    # create IdP session for SSO
    session["user"] = username

    resp_xml = build_saml_response(username, in_response_to=in_response_to, acs_url=acs, audience=sp_issuer)
    resp_b64 = base64.b64encode(etree.tostring(resp_xml)).decode("utf-8")
    return render_template("saml_post_form.html", acs_url=acs, saml_response=resp_b64, relay=relay)

@app.route("/metadata")
def metadata():
    # minimal metadata (not used by prototype, but useful)
    md = f"""<EntityDescriptor entityID="{IDP_ENTITY}">
  <IDPSSODescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_ENTITY}/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>"""
    return md, 200, {"Content-Type": "application/xml"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
