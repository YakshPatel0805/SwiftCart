from flask import Flask, render_template, request, redirect, url_for,flash
import bcrypt
from flask_mail import Mail, Message
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from pymongo import MongoClient
from bson.objectid import ObjectId
import json
import smtplib


app = Flask(__name__)
app.secret_key = '1a60d2a312818bb2b20170119f45e21a5a9053cc2504b42c69308125df2b6e25'

# Set up the MongoDB connection
client = MongoClient("mongodb://localhost:27017/")  # Replace with your MongoDB connection string if using a remote database
db = client["E-commerce"]  # Database name
login_collection = db["customer_data"]  # Collection name

# Secret key for session and token generation
app.config['SECRET_KEY'] = '1a60d2a312818bb2b20170119f45e21a5a9053cc2504b42c69308125df2b6e25'  # Change to a secure random key

# Set up Mail configuration (using Gmail as an example)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'esalpha337@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'Alpha@337#123'  # Replace with your email password
mail = Mail(app)


# URLSafeTimedSerializer for generating tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


#  =============================== Route Section ===========================================
@app.route('/')
def index():
    return render_template('index.html')


# Contact Form Route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Get the form data
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']

        # Create the email message
        msg = Message(subject=f"Contact Form Submission: {subject}",
                      recipients=["esalpha337@gmail.com"],  # Your email address to receive the message
                      body=f"Name: {name}\nEmail: {email}\nMessage: {message}")

        # Send the email
        try:
            mail.send(msg)
            flash("Your message has been sent successfully!", "success")
        except Exception as e:
            flash(f"An error occurred while sending your message: {str(e)}", "error")

        return redirect('/contact')  # Redirect to the contact page after submitting

    return render_template('contact.html')  # Render the contact form page


# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        signupemail = request.form['email']
        signupusername = request.form['username']
        signuppassword = request.form['password']
        retypepassword = request.form['repassword']

        # Check if the passwords match
        if signuppassword != retypepassword:
            return redirect(url_for('signup', error="Passwords do not match"))

        # Check if the username already exists in the database
        existing_user = login_collection.find_one({"username": signupusername})

        if existing_user:
            # If user exists, show an error
            return redirect(url_for('signup', error="Username already exists"))

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(signuppassword.encode('utf-8'), bcrypt.gensalt())

        # Insert the new user into MongoDB
        login_collection.insert_one({
            "email" : signupemail,
            "username": signupusername,
            "password": hashed_password.decode('utf-8'),
            "login_attempts": []  # Initially, there are no login attempts
        })

        # Redirect the user to the login page after successful signup
        return redirect(url_for('login'))

    return render_template('signup.html')  # Render signup page


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        loginemail = request.form['email']
        loginusername = request.form['username']
        loginpassword = request.form['password']

        # Fetch the stored password hash from MongoDB
        user = login_collection.find_one({"username": loginusername})

        if user:
            stored_hash = user["password"]

            # Check if the password matches
            if bcrypt.checkpw(loginpassword.encode('utf-8'), stored_hash.encode('utf-8')):
                # Insert login attempt into MongoDB
                login_collection.update_one(
                    {"_id": user["_id"]},
                    {"$push": {"login_attempts": {"success": True, "timestamp": "2025-02-17"}}}  # Insert login attempt
                )
                return redirect(url_for('dashboard'))
            else:
                # Insert failed login attempt into MongoDB
                login_collection.update_one(
                    {"_id": user["_id"]},
                    {"$push": {"login_attempts": {"success": False, "timestamp": "2025-02-17"}}}
                )
                return redirect(url_for('login', error="Incorrect Password"))
        else:
            return redirect(url_for('login', error="Incorrect Username or Password"))

    return render_template('login.html')


# Forgot Password Route
@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        username = request.form['username']
        user = login_collection.find_one({"username": username})

        if user:
            # Generate a unique token for password reset
            token = s.dumps(username, salt='password-reset')

            # Create a password reset URL
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send password reset email
            msg = Message('Password Reset Request', sender='esalpha337@gmail.com', recipients=[user['email']])
            msg.body = f'Click the following link to reset your password: {reset_url}'
            mail.send(msg)

            flash('Password reset link has been sent to your email.', 'info')
            return redirect(url_for('forgot'))
        else:
            flash('Username not found.', 'error')
            return redirect(url_for('forgot'))

    return render_template('forget.html')

# Reset Password Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify the token and get the username
        username = s.loads(token, salt='password-reset', max_age=3600)  # 1 hour expiration
    except:
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update password in MongoDB
        login_collection.update_one({'username': username}, {'$set': {'password': hashed_password.decode('utf-8')}})

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')


checkout_collection = db["checkoutlist"]  # Collection to store checkout data

# Checkout Route
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == "POST":
        # Extract shipping information from form data
        name = request.form['name']
        email = request.form['email']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        zipcode = request.form['zipcode']
        country = request.form['country']

        # Extract payment information from form data
        payment_method = request.form['payment-method']
        card_name = request.form.get('card-name')  # For credit card info
        card_number = request.form.get('card-number')
        exp_date = request.form.get('exp-date')
        cvv = request.form.get('cvv')
        paypal_email = request.form.get('paypal-email')  # For PayPal
        account_number = request.form.get('account-number')  # For bank transfer
        routing_number = request.form.get('routing-number')

        # Example of order summary
        # cart_items = json.loads(request.form['cart-items'])  # Assuming you pass cart items as JSON in hidden form field
        # total_amount = float(request.form['total-amount'])  # Assuming the total is passed as a hidden form field

        # Create a checkout data dictionary
        checkout_data = {
            "shipping_info": {
                "name": name,
                "email": email,
                "address": address,
                "city": city,
                "state": state,
                "zipcode": zipcode,
                "country": country
            },
            "payment_info": {
                "payment_method": payment_method,
                "card_info": {
                    "cardholder_name": card_name,
                    "card_number": card_number,
                    "exp_date": exp_date,
                    "cvv": cvv
                } if payment_method == 'credit-card' else None,
                "paypal_info": {
                    "paypal_email": paypal_email
                } if payment_method == 'paypal' else None,
                "bank_transfer_info": {
                    "account_number": account_number,
                    "routing_number": routing_number
                } if payment_method == 'bank-transfer' else None
            }
            # "order_summary": {
            #     "cart_items": cart_items,
            #     "total_amount": total_amount
            # }
        }

        # Insert the checkout data into MongoDB
        checkout_collection.insert_one(checkout_data)

        # Flash a success message and redirect
        flash("Your order has been placed successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to the dashboard or order confirmation page

    return render_template('checkout.html')  # Render the checkout page


@app.route('/cloth_alpha')
def cloth_alpha():
    return render_template('cloths_alpha.html')

@app.route('/electronic_alpha')
def electronic_alpha():
    return render_template('electronic_alpha.html')

@app.route('/furniture_alpha')
def furniture_alpha():
    return render_template('furniture_alpha.html')


@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/logout')
def logout():
    return render_template('logout.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')


# @app.route('/order', methods=['POST'])
# def order():
#     if request.method == 'POST':
#         # Get order details from form or request
#         customer_name = request.form['name']
#         customer_email = request.form['email']

#         # Create email message
#         msg = Message('New Order Received',  recipients=['esalpha337@gmail.com'])  # Your email to receive the order
#         msg.body = f"New order details:\n\nCustomer Name: {customer_name}\nEmail: {customer_email}"
#            # \n Order Details: {order_details}
#         try:
#             # Send the email
#             mail.send(msg)
#             return "Order placed successfully. A confirmation email has been sent."
#         except Exception as e:
#             return f"Error sending email: {str(e)}"

#     return "Your Order Is Placed"


if __name__ == '__main__':
    app.run(debug=True)