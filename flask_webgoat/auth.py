from flask import Blueprint, request, jsonify, session, redirect
from . import query_db

def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username is None or password is None:
        return (
            jsonify({"error": "username and password parameter have to be provided"}),
            400,
        )

    # Basic input validation to avoid extremely long or non-string inputs
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 256 or len(password) > 256:
        return jsonify({"error": "invalid input"}), 400

    # PRECOGS_FIX: Use parameterized query instead of string interpolation to prevent SQL injection
    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    # PRECOGS_FIX: Pass user-supplied values as parameters to query_db rather than formatting them into the SQL
    result = query_db(query, (username, password), True)

    if result is None:
        return jsonify({"bad_login": True}), 400
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})


@bp.route("/login_and_redirect")
def login_and_redirect():
    username = request.args.get("username")
    password = request.args.get("password")
    url = request.args.get("url")
    if username is None or password is None or url is None:
        return (
            jsonify(
                {"error": "username, password, and url parameters have to be provided"}
            ),
            400,
        )

    query = "SELECT id, username, access_level FROM user WHERE username = ? AND password = ?"
    result = query_db(query, (username, password), True)
    if result is None:
        # vulnerability: Open Redirect
        return redirect(url)
    session["user_info"] = (result[0], result[1], result[2])
    return jsonify({"success": True})
