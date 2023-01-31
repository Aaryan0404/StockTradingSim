import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, make_response
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    if request.method == "POST" or "GET":

        #Retrieve the current user's username and cash balance
        f = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])
        current_username = f[0]["username"]
        current_cash = f[0]["cash"]

        #Create a grouped table with groups of all the unique stock_symbols purchased by the user
        mm = db.execute("SELECT * FROM purchase_history WHERE username = :username GROUP BY stock_symbol", username=current_username)

        #Update the stock_price for each stock_symbol in the purchase-history table
        if len(mm) > 0:
            for m in mm:
                b = str(m["stock_symbol"])
                a = lookup(b)
                new_stock_price = a.get("price")
                db.execute("UPDATE purchase_history SET stock_price = :price WHERE stock_symbol = :d", price=new_stock_price, d=m["stock_symbol"])

        #Create a grouped table with groups of all the unique stock_symbols purchased, including number_of_shares and stock_price for each unique stock_symbol
        stocks = db.execute("SELECT stock_symbol, SUM(number_of_shares) as total_shares, stock_price FROM purchase_history WHERE username = :username GROUP BY stock_symbol HAVING total_shares > 0", username=current_username)

        #Calculate the value of all the stocks (all stock_symbols combined)
        value = 0
        if len(stocks) > 0:
            for stock in stocks:
                t = stock["stock_price"]
                u = stock["total_shares"]
                value = value + (t * u)

        #Calculate the grand total by adding the user's cash balance and total stock value
        grand_total = value + current_cash

        #Redirects user to index.html
        return render_template("index.html", stocks=stocks, current_cash=current_cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #Ensure stock-type input is not blank
        if not request.form.get("symbol"):
            return apology("Please enter the symbol of the stock you would like to purchase")

        #Ensure stock-type input exists
        if lookup(request.form.get("symbol")) == None:
            return apology("Please enter a valid stock symbol")

        #Ensure number-of-stocks input is valid
        if not request.form.get("shares"):
            return apology("Please enter a valid input regarding the number of shares you would like to purchase", 400)
        try:
            val = int(request.form.get("shares"))
        except ValueError:
            return apology("Please enter a valid input regarding the number of shares you would like to purchase", 400)
        if float(request.form.get("shares")) <= 0 or float(request.form.get("shares")).is_integer() == False:
            return apology("Please enter a valid input regarding the number of shares you would like to purchase", 400)

        #Retrieve current stock price and calculate total purchase price according to the number of shares requested
        a = lookup(request.form.get("symbol"))
        current_stock_price = a.get("price")
        number_of_shares_requested = request.form.get("shares")
        total_purchase_price = float(number_of_shares_requested) * current_stock_price

        #Retrieve from SQL database: user's current cash and user's username
        f = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session["user_id"])
        current_cash = f[0]["cash"]
        purchasing_username = f[0]["username"]

        #Proceeed with transaction if user has enough money
        if float(current_cash) >= total_purchase_price:

            #Calculate remaining cash after transaction and update information in the users table
            updated_cash = current_cash - total_purchase_price
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=updated_cash, user_id=session["user_id"])

            #Insert transaction information in purchase-history table
            db.execute("INSERT INTO purchase_history (username, stock_symbol, stock_price, number_of_shares) VALUES (:username, :symbol, :price, :number)", username=purchasing_username, symbol=request.form.get("symbol"), price=current_stock_price, number=number_of_shares_requested)

            #Redirect to homepage
            return redirect("/")

        #If unable to proceed with transaction, return apology
        else:
            return apology("You do not have enough money to complete the requested stock-purchase transaction")

    elif request.method == "GET":
        return render_template("buy.html")



@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    if request.method == "GET":
        username = request.args.get("username")
        if len(username) >= 1:
            uuu = db.execute("SELECT * FROM users WHERE username = :a", a=username)
            if len(uuu) == 0:
                return jsonify(True)
            else:
                return jsonify(False)
        else:
            return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    f = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])
    current_username = f[0]["username"]
    bigs = db.execute("SELECT * FROM purchase_history WHERE username = :username", username=current_username)
    return render_template("history.html", bigs=bigs)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via GET
    if request.method == "GET":
        return render_template("quote.html")

    # User reached route via POST
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("please enter a stock symbol", 400)
        else:
            stock_symbol = request.form.get("symbol")
            a = lookup(stock_symbol)
        if a == None:
            return apology("please enter a valid stock symbol", 400)
        stock_symbol = a.get("symbol")
        stock_quote = usd(a.get("price"))
        return render_template("quoted.html", stock=stock_symbol, price=stock_quote)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        #Ensure username input exists
        if not request.form.get("username"):
            return apology("Must register for a username", 400)

        # Query database to check whether the username already exisits
        abc = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(abc) != 0:
            return apology("Username inputted has already been taken", 400)

        #Ensure password input exists
        if not request.form.get("password"):
            return apology("Must register for a account password", 400)

        #Ensure password confirmation input exists
        if not request.form.get("confirmation"):
            return apology("Must confirm account password", 400)

        #Ensure password input matches password confirmation input
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Confirmation input must match password input", 400)

        new_user_username = request.form.get("username")
        new_user_password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        defa = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hashy)", username=new_user_username, hashy=new_user_password)

        session["user_id"] = defa
        return redirect("/")

    elif request.method == "GET":
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    r = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])
    current_username = r[0]["username"]

    if request.method == "GET":
        amc = db.execute("SELECT stock_symbol, SUM(number_of_shares) as total_shares FROM purchase_history WHERE username = :username GROUP BY stock_symbol HAVING total_shares > 0", username=current_username)

        if len(amc) == 0:
            return apology("You currently own no shares of any stock to sell", 400)
        else:
            return render_template("sell.html", amc=amc)
    else:
        if not request.form.get("symbol"):
            return apology("Please select a stock-symbol to indicate which stock you would like to sell", 400)
        if not request.form.get("shares"):
            return apology("Please enter a valid input for the number of shares you would like to sell", 400)
        if int(request.form.get("shares")) <= 0:
            return apology("You cannot sell a non-positive number of shares", 400)

        e = db.execute("SELECT SUM(number_of_shares) as total_shares FROM purchase_history WHERE username = :username AND stock_symbol = :symbol GROUP BY stock_symbol", username=current_username, symbol=request.form.get("symbol"))
        if int(request.form.get("shares")) > int(e[0]["total_shares"]):
            return apology("The transaction is unable to proceed as you do not own any shares of the stock you wish to sell", 400)

        current_price_of_stock = (lookup(request.form.get("symbol")))["price"]
        total_value_of_sell = float((request.form.get("shares"))) * current_price_of_stock
        w = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        updated_cash = w[0]["cash"] + total_value_of_sell
        ey = (-1) * int(request.form.get("shares"))

        db.execute("INSERT INTO purchase_history (username, stock_symbol, stock_price, number_of_shares) VALUES(:username, :stock_symbol, :stock_price, :number_of_shares)", username=current_username, stock_symbol=request.form.get("symbol"), stock_price=current_price_of_stock, number_of_shares=ey)
        db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", cash=updated_cash, user_id=session["user_id"])

        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
