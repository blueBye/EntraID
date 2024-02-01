import os

from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session
from dotenv import load_dotenv, dotenv_values
import msal

load_dotenv()


app = Flask(__name__)
app.config.from_object(dotenv_values())
sess = Session(app)
app.secret_key = "randomSecret"
app.config['SESSION_TYPE'] = os.getenv("SESSION_TYPE")
sess.init_app(app)


@app.route("/")
def index():
    # initiate authentication flow
    if not session.get("user"):
        cca = _build_masl_app()
        session["flow"] = cca.initial_auth_code_flow(
            os.getenv("SCOPES"), url_for("redir", _external=True))
        return render_template("index.html",
                               auth_uri=session["flow"]["auth_uri"])
    return render_template("index.html", user=session["user"])


@app.route("/redir")
def rdir():
    # finish the authentication process (getting tokens)
    cca = _build_masl_app()
    result = cca.acquire_token_by_auth_code_flow(
        session.get("flow", {}), request.args)
    session["user"] = result.get("id_token_claims")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        os.getenv("AUTHORITY") + "oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))


def _build_masl_app():
    return msal.ConfidentialClientApplication(
        os.getenv("CLIENT_ID"),
        authority=os.getenv("AUTHORITY"),
        client_credential=os.getenv("CLIENT_SECRET")
    )
