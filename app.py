from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.utils import secure_filename
import boto3
import uuid

app = Flask(__name__)
app.secret_key = '1234567890'

# AWS Configuration
AWS_ACCESS_KEY = ''
AWS_SECRET_KEY = ''
AWS_REGION = ''
S3_BUCKET = ''
DYNAMO_TABLE = ''

# Initialize AWS services
s3 = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

dynamodb = boto3.resource(
    'dynamodb',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)
table = dynamodb.Table(DYNAMO_TABLE)

# Routes
@app.route('/')
def index():
    return render_template('register.html')

@app.route("/loginpage")
def loginpage():
    return render_template('login.html')

@app.route('/registerUser', methods=['POST'])
def register_user():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Store plain text password (not recommended for production)
    table.put_item(
        Item={
            'email': email,
            'username': name,
            'password': password,  # Storing password in plain text
            'profile_pic': ''
        }
    )
    return render_template('login.html')

from boto3.dynamodb.conditions import Key

@app.route('/loginUser', methods=['POST'])
def login_user():
    email = request.form['email']
    username = request.form['username']  # Get the username from form input
    password = request.form['password']

    try:
        # Query DynamoDB using both Partition Key (email) and Sort Key (username)
        response = table.get_item(
            Key={'email': email, 'username': username}
        )

        # Check if a user was found
        user = response.get('Item')
        if user:
            # Debugging - Print user info
            print(f"User data fetched from DB: {user}")
            print(f"Entered password: {password}")

            # Check password
            if user['password'] == password:
                session['username'] = user['username']
                session['email'] = user['email']
                return redirect('/dashboard')

        # If no user is found or password is incorrect
        return render_template('login.html', error="Invalid email, username, or password")

    except Exception as e:
        print(f"Error: {str(e)}")
        return render_template('login.html', error="An error occurred. Please try again.")



@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        # If email is not found in session, redirect to the login page
        return redirect('/')

    # Get user data from DynamoDB using the email stored in the session
    user = table.get_item(
        Key={'email': session['email'],"username":session['username']}
    ).get('Item', {})

    # Render the dashboard template with user details
    return render_template('dashboard.html',
                           profile_pic=user.get('profile_pic', ''),
                           username=session['username'])


@app.route('/uploadProfilePic', methods=['POST'])
def upload_profile_pic():
    if 'email' not in session:
        return redirect('/')
        
    if 'profile_pic' not in request.files:
        return redirect('/dashboard')
        
    file = request.files['profile_pic']
    if file.filename == '':
        return redirect('/dashboard')
        
    # Create unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"profile_pics/{session['email']}/{uuid.uuid4()}_{filename}"
    
    # Upload to S3
    try:
        s3.upload_fileobj(
            file,
            S3_BUCKET,
            unique_filename,
            ExtraArgs={'ACL': 'public-read'}
        )
        
        # Create S3 URL
        file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{unique_filename}"
        
        # Update DynamoDB with profile picture URL
        table.update_item(
            Key={'email': session['email'],"username":session['username']},
            UpdateExpression="set profile_pic = :p",
            ExpressionAttributeValues={':p': file_url}
        )
    except Exception as e:
        print(f"Error: {str(e)}")
    
    return redirect('/dashboard')

@app.route('/listFiles')
def list_files():
    if 'email' not in session:
        return redirect('/')

    try:
        # Fetch all files from S3 bucket
        response = s3.list_objects_v2(Bucket=S3_BUCKET)
        files = []

        if 'Contents' in response:
            for obj in response['Contents']:
                file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{obj['Key']}"
                files.append(file_url)

        return render_template('list_files.html', files=files)

    except Exception as e:
        print(f"Error: {str(e)}")
        return "Error fetching files."



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
