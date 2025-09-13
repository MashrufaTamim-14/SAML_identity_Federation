from flask import Flask, session, redirect, request, render_template, url_for
import base64, uuid
from lxml import etree

app = Flask(__name__)
app.secret_key = "sp1-dev-secret"

SP_ENTITY = "http://sp1.example.com:5001"
IDP_SSO = "http://127.0.0.1:5000/sso"

def build_authn_request(acs_url):
    rid = "_" + uuid.uuid4().hex
    req = etree.Element("AuthnRequest", ID=rid, Version="2.0", AssertionConsumerServiceURL=acs_url)
    issuer = etree.SubElement(req, "Issuer")
    issuer.text = SP_ENTITY
    return rid, etree.tostring(req)

@app.route("/")
def index():
    logged = session.get("user") is not None
    name = session.get("user")
    return render_template("index.html", logged=logged, name=name)

@app.route("/service")
def service():
    # Service page requires login
    if not session.get("user"):
        return redirect(url_for("start_login"))
    return "<h3>Protected Service 1 content — Welcome %s</h3>" % session.get("user")

@app.route("/start_login")
def start_login():
    # show IdP selection page (in real world you'd list many IdPs)
    return render_template("idp_select.html", idps=[{"entity":"idp1.example.com","sso":IDP_SSO}], acs=url_for("acs", _external=True))

@app.route("/redirect_to_idp", methods=["POST"])
def redirect_to_idp():
    # Called when user picks an IdP on selection page
    idp_sso = request.form.get("idp_sso")
    acs = request.form.get("acs")
    rid, req_xml = build_authn_request(acs)
    req_b64 = base64.b64encode(req_xml).decode("utf-8")
    # store the AuthnRequest ID in session so we can match InResponseTo later
    session["authn_request_id"] = rid
    # redirect to IdP /sso with the saml_request param
    return redirect(f"{idp_sso}?saml_request={req_b64}&relay=sp1")

@app.route("/acs", methods=["POST"])
def acs():
    saml_resp_b64 = request.form.get("SAMLResponse")
    relay = request.form.get("RelayState","")
    if not saml_resp_b64:
        return "Missing SAMLResponse", 400
    try:
        xml = base64.b64decode(saml_resp_b64)
        doc = etree.fromstring(xml)
    except Exception as e:
        return f"Bad SAMLResponse: {e}", 400

    in_response_to = doc.get("InResponseTo")
    expected = session.get("authn_request_id")
    if not expected or in_response_to != expected:
        return "Invalid InResponseTo (possible replay or mismatch)", 400

    # extract NameID
    nameid_el = doc.find(".//NameID")
    user = nameid_el.text if nameid_el is not None else "unknown"
    # create SP session
    session["user"] = user
    return redirect(url_for("service"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
