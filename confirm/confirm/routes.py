from flask import render_template, request, url_for, redirect, flash
from confirm import app, db, bcrypt, mail
import tweepy
import pandas as pd
import matplotlib
#matplotlib.use('Agg')
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from textblob import TextBlob
import seaborn as sns
import re
from confirm.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from confirm.models import User
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from googletrans import Translator
import os

@app.route('/')
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('login'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/home")
@login_required
def home():
    return render_template('index.html')


@app.errorhandler(404)
def page_not_found():
    return render_template('client.html')


@app.errorhandler(405)
def page_not_found():
    return render_template('server.html')


@app.errorhandler(500)
def page_not_found():
    return render_template('server.html')


@app.route("/about")
def about():
    return render_template('about.html')


@app.route("/hashtag")
@login_required
def hashtag():
    return render_template('hashtag.html')


@app.route("/handle")
@login_required
def handle():
    return render_template('word.html')


@app.route("/wordcloud")
@login_required
def wordcloud():
    return render_template('wordcloud.html')


@app.route("/barchart")
@login_required
def barchart():
    return render_template('barchart.html')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='team3updates@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


consumerKey = "hXaobeJVWNdJUQv0rwckeqOfF"
consumerSecret = "XCfE9N7v8NVnrdvlMx0MUFHL7kYCR6qxxEWR7BX2AFqB8EwgkO"
accessToken = "2865723461-CPWRYnviu6X2f7ugEPmhtuofgvNljL8Z0L7VZbs"
accessTokenSecret = "QWM5dATE4d7wpZW59xITELkFUe8JXSQWnUqFgA2GFr6rL"
authenticate = tweepy.OAuthHandler(consumerKey, consumerSecret)
authenticate.set_access_token(accessToken, accessTokenSecret)
api = tweepy.API(authenticate, wait_on_rate_limit=True)


@app.route("/analyse", methods=['POST'])
@login_required
def analyse():
    if request.method == 'POST':
        if request.form['Show Recent Tweets'] == 'Show Recent Tweets':
            raw_text = request.form.get('rawtext')
            try:
                posts = api.user_timeline(screen_name=raw_text, count=100, lang="en", tweet_mode="extended")

                def get_tweets():
                    l = []
                    i = 1
                    for tweet in posts[:5]:
                        l.append(tweet.full_text)
                    i = i + 1
                    return l
                recent_tweets = get_tweets()
                return render_template('word.html', n=recent_tweets)
            except:
                recent_tweets = "The twitter handle that you entered is not valid!!!!!"
                return render_template('word.html', error=recent_tweets)


@app.route("/keyhash", methods=['POST'])
def keyhash():
    if request.method == 'POST':
        hashtag = request.form.get('hashtag')
        try:
            posts = api.search(q=hashtag, lang='en', count=100, tweet_mode='extended')

            def get_tweets():
                l = []
                i = 1
                for tweet in posts[:5]:
                    l.append(tweet.full_text)
                i = i + 1
                return l

            recent_tweets = get_tweets()
            return render_template('hashtag.html', n=recent_tweets)
        except:
            recent_tweets = "The hashtag or term you entered is not in twitter!!!!!"
            return render_template('hashtag.html', error=recent_tweets)

@app.route("/Wordcloud", methods=['POST'])
@login_required
def gen_wordcloud():
    if request.method == 'POST':
        raw_text = request.form.get('rawtext')
        try:
            posts = api.user_timeline(screen_name=raw_text, count=100, lang="en", tweet_mode="extended")
            # Create a dataframe with a column called Tweets
            df = pd.DataFrame([tweet.full_text for tweet in posts], columns=['Tweets'])
            #translate any language to English
            try:
                translator = Translator()
                df.rename(columns=lambda x: translator.translate(x).text, inplace=True)
                translations = {}
                for column in df.columns:
                    # unique elements of the column
                    unique_elements = df[column].unique()
                    for element in unique_elements:
                        # add translation to the dictionary
                        translations[element] = translator.translate(element, dest='en').text
                df.replace(translations, inplace=True)
            finally:
                # Clean the tweets
                def cleanTxt(text):
                    text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                    text = re.sub('#', '', text)  # Removing '#' hash tag
                    text = re.sub('RT[\s]+', '', text)  # Removing RT
                    text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                    return text

                # word cloud visualization
                df['Tweets'] = df['Tweets'].apply(cleanTxt)
                allWords = ' '.join([twts for twts in df['Tweets']])
                wordCloud = WordCloud(width=500, height=300, random_state=21, max_font_size=110).generate(allWords)
                plt.imshow(wordCloud, interpolation="bilinear")
                plt.axis('off')
                plt.savefig('confirm/static/images/first_review.png', bbox_inches='tight')
                plt.clf()
                return render_template('wordcloud.html', result="Wordcloud for " + raw_text)
        except:
            recent_tweets = "The twitter handle that you entered is not valid!!!!!"
            return render_template('word.html', error=recent_tweets)




@app.route("/hashcloud", methods=['POST'])
@login_required
def gen_hashcloud():
    if request.method == 'POST':
        hashtag = request.form.get('hashtag')
        try:
            posts = api.search(q=hashtag, lang='en', count=100, tweet_mode='extended')
            # Create a dataframe with a column called Tweets
            df = pd.DataFrame([tweet.full_text for tweet in posts], columns=['Tweets'])
            #translate any language to English
            try:
                translator = Translator()
                df.rename(columns=lambda x: translator.translate(x).text, inplace=True)
                translations = {}
                for column in df.columns:
                    # unique elements of the column
                    unique_elements = df[column].unique()
                    for element in unique_elements:
                        # add translation to the dictionary
                        translations[element] = translator.translate(element).text
                df.replace(translations, inplace=True)
            finally:
                def cleanTxt(text):
                    text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                    text = re.sub('#', '', text)  # Removing '#' hash tag
                    text = re.sub('RT[\s]+', '', text)  # Removing RT
                    text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                    return text

                # word cloud visualization
                df['Tweets'] = df['Tweets'].apply(cleanTxt)
                allWords = ' '.join([twts for twts in df['Tweets']])
                wordCloud = WordCloud(width=500, height=300, random_state=21, max_font_size=110).generate(allWords)
                plt.imshow(wordCloud, interpolation="bilinear")
                plt.axis('off')
                plt.savefig('confirm/static/images/first_review.png', bbox_inches='tight')
                plt.clf()
                return render_template('wordcloud.html', result="Wordcloud for " + hashtag)

            # Clean the tweets

        except:
            recent_tweets = "The hashtag or term you entered is not in twitter!!!!!"
            return render_template('hashtag.html', error=recent_tweets)


@app.route("/vivo", methods=['POST'])
@login_required
def Plot_Analysis():
    if request.method == 'POST':
        raw_text = request.form.get('rawtext')
        try:

            posts = api.user_timeline(screen_name=raw_text, count=100, lang="en", tweet_mode="extended")
            # Create a dataframe with a column called Tweets
            df = pd.DataFrame([tweet.full_text for tweet in posts], columns=['Tweets'])
            # translate any language to English
            try:
                translator = Translator()
                df.rename(columns=lambda x: translator.translate(x).text, inplace=True)
                translations = {}
                for column in df.columns:
                    # unique elements of the column
                    unique_elements = df[column].unique()
                    for element in unique_elements:
                        # add translation to the dictionary
                        translations[element] = translator.translate(element).text
                df.replace(translations, inplace=True)
            # Create a function to clean the tweets
            finally:
                def cleanTxt(text):
                    text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                    text = re.sub('#', '', text)  # Removing '#' hash tag
                    text = re.sub('RT[\s]+', '', text)  # Removing RT
                    text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                    return text

                # Clean the tweets
                df['Tweets'] = df['Tweets'].apply(cleanTxt)

                # Create a function to get the subjectivity
                def getSubjectivity(text):
                    return TextBlob(text).sentiment.subjectivity

                # Create a function to get the polarity
                def getPolarity(text):
                    return TextBlob(text).sentiment.polarity

                # Create two new columns 'Subjectivity' & 'Polarity'
                df['Subjectivity'] = df['Tweets'].apply(getSubjectivity)
                df['Polarity'] = df['Tweets'].apply(getPolarity)

                def getAnalysis(score):

                    if score < 0:
                        return 'Negative'
                    elif score == 0:
                        return 'Neutral'
                    else:
                        return 'Positive'

                df['Analysis'] = df['Polarity'].apply(getAnalysis)
                sns.countplot(x=df["Analysis"], data=df)
                plt.savefig("confirm/static/images/new_plot.png")
                plt.clf()
                return render_template('barchart.html', result="Bar Chart for " + raw_text)
        except:
            recent_tweets = "The twitter handle that you entered is not valid!!!!!"
            return render_template('word.html', error=recent_tweets)

@app.route("/hashabar", methods=['POST'])
@login_required
def hashabar():
    if request.method == 'POST':
        hashtag = request.form.get('hashtag')
        try:
            #posts = api.search(q=hashtag, lang='en', count=100, tweet_mode='extended')
            # Create a dataframe with a column called Tweets
            #df = pd.DataFrame([tweet.full_text for tweet in posts], columns=['Tweets'])
            # translate any language to English
            posts = tweepy.Cursor(api.search, q=hashtag, lang='en', count=100).items(5000)
            df = pd.DataFrame([tweet.text for tweet in posts], columns=['Tweets'])
            try:
                translator = Translator()
                df.rename(columns=lambda x: translator.translate(x).text, inplace=True)
                translations = {}
                for column in df.columns:
                    # unique elements of the column
                    unique_elements = df[column].unique()
                    for element in unique_elements:
                        # add translation to the dictionary
                        translations[element] = translator.translate(element).text
                df.replace(translations, inplace=True)
            # Create a function to clean the tweets
            finally:
                def cleanTxt(text):
                    text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                    text = re.sub('#', '', text)  # Removing '#' hash tag
                    text = re.sub('RT[\s]+', '', text)  # Removing RT
                    text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                    return text

                # Clean the tweets
                df['Tweets'] = df['Tweets'].apply(cleanTxt)

                # Create a function to get the subjectivity
                def getSubjectivity(text):
                    return TextBlob(text).sentiment.subjectivity

                # Create a function to get the polarity
                def getPolarity(text):
                    return TextBlob(text).sentiment.polarity

                # Create two new columns 'Subjectivity' & 'Polarity'
                df['Subjectivity'] = df['Tweets'].apply(getSubjectivity)
                df['Polarity'] = df['Tweets'].apply(getPolarity)

                def getAnalysis(score):

                    if score < 0:
                        return 'Negative'
                    elif score == 0:
                        return 'Neutral'
                    else:
                        return 'Positive'

                df['Analysis'] = df['Polarity'].apply(getAnalysis)
                sns.countplot(x=df["Analysis"], data=df)
                plt.savefig("confirm/static/images/new_plot.png")
                plt.clf()
                return render_template('barchart.html', result="Bar Chart for " + hashtag)
        except:
            recent_tweets = "The hashtag or term you entered is not twitter!!!!!"

            return render_template('hashtag.html', error=recent_tweets)

@app.route("/fetch", methods=['POST'])
def get_data():
    if request.method == 'POST':
        user_name = request.form.get('visualize')
        try:
            posts = api.user_timeline(screen_name=user_name,count=100, lang="en", tweet_mode="extended")

            df = pd.DataFrame([tweet.full_text for tweet in posts], columns=['Tweets'])
            try:
                translator = Translator()
                df.rename(columns=lambda x: translator.translate(x).text, inplace=True)
                translations = {}
                for column in df.columns:
                    # unique elements of the column
                    unique_elements = df[column].unique()
                    for element in unique_elements:
                        # add translation to the dictionary
                        translations[element] = translator.translate(element).text
                df.replace(translations, inplace=True)
            finally:
                def cleanTxt(text):
                    text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                    text = re.sub('#', '', text)  # Removing '#' hash tag
                    text = re.sub('RT[\s]+', '', text)  # Removing RT
                    text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                    return text

                # Clean the tweets
                df['Tweets'] = df['Tweets'].apply(cleanTxt)

                def getSubjectivity(text):
                    return TextBlob(text).sentiment.subjectivity

                # Create a function to get the polarity
                def getPolarity(text):
                    return TextBlob(text).sentiment.polarity

                # Create two new columns 'Subjectivity' & 'Polarity'
                df['Subjectivity'] = df['Tweets'].apply(getSubjectivity)
                df['Polarity'] = df['Tweets'].apply(getPolarity)

                def getAnalysis(score):
                    if score < 0:
                        return 'Negative'
                    elif score == 0:
                        return 'Neutral'
                    else:
                        return 'Positive'

                df['Analysis'] = df['Polarity'].apply(getAnalysis)
                new = df.to_html()
                return new
        except:
            recent_tweets = "The twitter handle that you entered is not valid!!!!!"
            return render_template('word.html', error=recent_tweets)
import csv
@app.route("/hashfetch", methods=['POST'])
def hash():
    if request.method == 'POST':
        hashtag = request.form.get('visualize')
        try:
            # Open/Create a file to append data

            #csvFile = open('ua.csv', 'a')
            # Use csv Writer
            #csvWriter = csv.writer(csvFile)
            posts = tweepy.Cursor(api.search,q=hashtag, lang='en', count=100).items(5000)
            df = pd.DataFrame([tweet.text for tweet in posts], columns=['Tweets'])
            #for tweet in tweepy.Cursor(api.search, q=hashtag, count=100,lang="en",since="2020-12-14").items(5000):
                #print(tweet.created_at, tweet.text)
                #csvWriter.writerow(["Tweets"])
                #csvWriter.writerow([tweet.text.encode('utf-8')])
                #posts = api.search(q=hashtag, lang='en',count=100 ,tweet_mode='extended')

            #df = pd.read_csv('ua.csv', columns=['Tweets'])
           #df.to_csv('out.csv')

            def cleanTxt(text):
                text = re.sub('@[A-Za-z0–9]+', '', text)  # Removing @mentions
                text = re.sub('#', '', text)  # Removing '#' hash tag
                text = re.sub('RT[\s]+', '', text)  # Removing RT
                text = re.sub('https?:\/\/\S+', '', text)  # Removing hyperlink
                return text

            # Clean the tweets

            df['Tweets'] = df['Tweets'].apply(cleanTxt)

            def getSubjectivity(text):
                return TextBlob(text).sentiment.subjectivity

            # Create a function to get the polarity
            def getPolarity(text):
                return TextBlob(text).sentiment.polarity

            # Create two new columns 'Subjectivity' & 'Polarity'
            df['Subjectivity'] = df['Tweets'].apply(getSubjectivity)
            df['Polarity'] = df['Tweets'].apply(getPolarity)

            def getAnalysis(score):
                if score < 0:
                     return 'Negative'
                elif score == 0:
                     return 'Neutral'
                else:
                     return 'Positive'

            df['Analysis'] = df['Polarity'].apply(getAnalysis)
            count = df['Analysis'].value_counts(normalize=True)
            print(hashtag)
            print(count*100)

            #df.to_csv('out.csv')
            new=df.to_html()
            return new
        except:
            recent_tweets = "The hashtag or term you entered is not in twitter!!!!!"
            return render_template('hashtag.html', error=recent_tweets)










