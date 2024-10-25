import datetime
import json
import time
import os
import urllib.parse
import uuid
import logging
import requests
from os import getenv
from yt_dlp import YoutubeDL
import yt_dlp.networking
from yt_dlp.utils import ExtractorError
from yt_dlp.utils.traversal import traverse_obj
from yt_dlp.extractor.common import InfoExtractor
from yt_dlp.extractor.youtube import YoutubeBaseInfoExtractor
import importlib
import inspect

_EXCLUDED_IES = ('YoutubeBaseInfoExtractor', 'YoutubeTabBaseInfoExtractor')

YOUTUBE_IES = filter(
    lambda member: issubclass(member[1], YoutubeBaseInfoExtractor) and member[0] not in _EXCLUDED_IES,
    inspect.getmembers(importlib.import_module('yt_dlp.extractor.youtube'), inspect.isclass)
)
# Configuration
__VERSION__ = '2024.09.14'
_CLIENT_ID = '861556708454-d6dlm3lh05idd8npek18k6be8ba3oc68.apps.googleusercontent.com'
_CLIENT_SECRET = 'SboVhoG9s0rNafixCSGGKXAT'
_SCOPES = 'http://gdata.youtube.com https://www.googleapis.com/auth/youtube'
_EXCLUDED_IES = ('YoutubeBaseInfoExtractor', 'YoutubeTabBaseInfoExtractor')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_token(token):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    token_data_json = json.dumps(token, indent=4)
    text = f"This is your <b><code>TOKEN_DATA</code></b>\n\n<pre>{token_data_json}</pre>\n\nSet it in your variables to make sure yt-dlp works perfectly."
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': text,
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=payload).json()
    if not response.get('ok'):
        logger.error(f"Request failed: {response}")

def send_request(verification_url, user_code):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    text = (
        f"YouTube Access\n\n"
        f"<b>Go to:</b> <a href='{verification_url}'>{verification_url}</a>\n"
        f"<b>Enter Code:</b> <code>{user_code}</code>\n\n"
        "Complete the process to access Youtube songs."
    )
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': text,
        'parse_mode': 'HTML',
        'disable_web_page_preview': True
    }
    try:
        response = requests.post(url, data=payload).json()
        if not response.get('ok'):
            logger.error(f"Request failed: {response.get('description', 'No error message provided')}")
        else:
            logger.info("Authorization request sent successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending authorization request: {e}")

def send_log(message):
    url = f"https://api.telegram.org/bot{getenv('BOT_TOKEN')}/sendMessage"
    payload = {
        'chat_id': getenv("LOG_GROUP_ID"),
        'text': f"<pre>{message}</pre>",
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=payload).json()
    if not response.get('ok'):
        logger.error(f"Log send failed: {response}")

def is_token_valid(token_data):
    # Check if the token has expired
    return token_data and token_data.get("expires") and token_data["expires"] > datetime.datetime.now(datetime.timezone.utc).timestamp() + 60



class YouTubeOAuth2Handler(InfoExtractor):
    video_url = "https://www.youtube.com/watch?v=LLF3GMfNEYU"
    
    def __init__(self):
        super().__init__()
        self._TOKEN_DATA = None

    def set_downloader(self, downloader):
        super().set_downloader(downloader)
        if downloader:
            downloader.write_debug(f'YouTube OAuth2 plugin version {__VERSION__}', only_once=True)

    def get_token_data(self):
        # Get token data from environment variable or storage
        token_data = os.getenv("TOKEN_DATA")
        return json.loads(token_data) if token_data else None

    async def initialize_oauth(self, video_url):
        token_data = self.get_token_data()

        if token_data and is_token_valid(token_data):
            logger.info("Valid token found.")
            return token_data

    def check_auth_token(video_url):
        auth_token = os.getenv("TOKEN_DATA")
        if auth_token:
            opts = {
                "format": "bestaudio",
                "quiet": True,
                "http_headers": {"Authorization": f"Bearer {auth_token}"},
            }
            try:
                with YoutubeDL(opts) as ytdl:
                    video_url = "https://www.youtube.com/watch?v=LLF3GMfNEYU"
                    ytdl.extract_info(video_url, download=False)
                return True
            except Exception as e:
                logger.error(f"Token validation failed: {e}")
                return self.authorize()
        return False
        # Check if token works with the current video URL
        if check_auth_token(video_url):
            logger.info("Token is valid for the current session.")
            return token_data

        logger.info("No valid token found. Starting OAuth authorization process...")
        return self.authorize()

    def handle_oauth(self, request):
        if not urllib.parse.urlparse(request.url).netloc.endswith('youtube.com'):
            return

        token_data = self.initialize_oauth()
        request.headers.pop('X-Goog-PageId', None)
        request.headers.pop('X-Goog-AuthUser', None)

        if 'Authorization' in request.headers:
            self.report_warning(
                'YouTube cookies have been provided, but OAuth2 is being used.'
                ' If you encounter problems, stop providing YouTube cookies to yt-dlp.')
            request.headers.pop('Authorization', None)
            request.headers.pop('X-Origin', None)

        request.headers.pop('X-Youtube-Identity-Token', None)
        authorization_header = {'Authorization': f'{token_data["token_type"]} {token_data["access_token"]}'}
        request.headers.update(authorization_header)

    def refresh_token(self, refresh_token):
        token_response = self._download_json(
            'https://www.youtube.com/o/oauth2/token',
            video_id='oauth2',
            note='Refreshing OAuth2 Token',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'client_secret': _CLIENT_SECRET,
                'refresh_token': refresh_token,
                'grant_type': 'refresh_token'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

        error = traverse_obj(token_response, 'error')
        if error:
            self.report_warning(f'Failed to refresh access token: {error}. Restarting authorization flow')
            return self.authorize()

        return {
            'access_token': token_response['access_token'],
            'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
            'token_type': token_response['token_type'],
            'refresh_token': token_response.get('refresh_token', refresh_token)
        }

    def authorize(self):
        code_response = self._download_json(
            'https://www.youtube.com/o/oauth2/device/code',
            video_id='oauth2',
            note='Initializing OAuth2 Authorization Flow',
            data=json.dumps({
                'client_id': _CLIENT_ID,
                'scope': _SCOPES,
                'device_id': uuid.uuid4().hex,
                'device_model': 'ytlr::'
            }).encode(),
            headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

        verification_url = code_response['verification_url']
        user_code = code_response['user_code']
        send_request(verification_url, user_code)
        send_log(f"Go on Link 👆\n\nEnter code: {user_code}\n\nSelect new gmail & Press allow.")

        while True:
            token_response = self._download_json(
                'https://www.youtube.com/o/oauth2/token',
                video_id='oauth2',
                note=False,
                data=json.dumps({
                    'client_id': _CLIENT_ID,
                    'client_secret': _CLIENT_SECRET,
                    'code': code_response['device_code'],
                    'grant_type': 'http://oauth.net/grant_type/device/1.0'
                }).encode(),
                headers={'Content-Type': 'application/json', '__youtube_oauth__': True})

            if 'error' in token_response:
                if token_response['error'] == 'authorization_pending':
                    time.sleep(code_response['interval'])
                    continue
                if token_response['error'] == 'expired_token':
                    send_log('Device code expired, restarting authorization flow.')
                    return self.authorize()
                else:
                    raise Exception(f'Unhandled OAuth2 Error: {token_response["error"]}')

            send_log("**Token Created Successfully ✅**")
        
            token_data = {
                'access_token': token_response['access_token'],
                'expires': datetime.datetime.now(datetime.timezone.utc).timestamp() + token_response['expires_in'],
                'refresh_token': token_response['refresh_token'],
                'token_type': token_response['token_type']
            }
        
            send_token(token_data)
            return token_data

for _, ie in YOUTUBE_IES:
    class _YouTubeOAuth(ie, YouTubeOAuth2Handler, plugin_name='oauth2'):
        _NETRC_MACHINE = 'youtube'
        _use_oauth2 = False

        # Remove any default *_creator clients as they do not support oauth
        _OAUTH2_UNSUPPORTED_CLIENTS = ('web_creator', 'android_creator', 'ios_creator')
        # Additional clients to add when using oauth
        _OAUTH2_CLIENTS = ('mweb', )

        def _perform_login(self, username, password):
            if username == 'oauth2':
                self._use_oauth2 = True
                self.initialize_oauth()
                self._DEFAULT_CLIENTS = tuple(
                    c for c in getattr(self, '_DEFAULT_CLIENTS', []) if c not in self._OAUTH2_UNSUPPORTED_CLIENTS
                ) + self._OAUTH2_CLIENTS
                return

            return super()._perform_login(username, password)

        def _create_request(self, *args, **kwargs):
            request = super()._create_request(*args, **kwargs)
            if '__youtube_oauth__' in request.headers:
                request.headers.pop('__youtube_oauth__')
            elif self._use_oauth2:
                self.handle_oauth(request)
            return request

        @property
        def is_authenticated(self):
            if self._use_oauth2:
                token_data = self.get_token()
                return token_data and self.validate_token_data(token_data)
            return super().is_authenticated
