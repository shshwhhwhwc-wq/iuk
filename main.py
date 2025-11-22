import re as ree
import requests
import json
import uuid
import random
import time
import base64
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler

# States
USERNAME, PASSWORD, VERIFY_METHOD, VERIFY_CODE, TWO_FA_METHOD, TWO_FA_CODE = range(6)

# Session storage
user_sessions = {}

def generate_ids():
    return {
        "qe_device_id": str(uuid.uuid4()),
        "family_device_id": str(uuid.uuid4()),
        "device_id": f"android-{uuid.uuid4().hex[:16]}",
        "machine_id": f"a{uuid.uuid4().hex[:12]}",
        "waterfall_id": str(uuid.uuid4()),
        "pigeon_session_id": f"UFS-{uuid.uuid4()}-0",
        "bandwidth_speed": f"{random.uniform(500, 5000):.3f}",
        "bandwidth_totalbytes": str(random.randint(200000, 900000)),
        "bandwidth_totaltime": str(random.randint(100, 800)),
        "rawclienttime": str(time.time()),
        "bloks_version": "e061cacfa956f06869fc2b678270bef1583d2480bf51f508321e64cfb5cc12bd",
        "app_id": "567067343352427",
    }

def extract_session_from_token(token):
    try:
        if token.startswith('Bearer '):
            token = token.replace('Bearer ', '')
        if token.startswith('IGT:2:'):
            token = token.split(':', 2)[2]
        decoded_bytes = base64.b64decode(token)
        decoded_data = decoded_bytes.decode('utf-8')
        auth_data = json.loads(decoded_data)
        return auth_data.get('sessionid', '')
    except Exception as e:
        return None

def login(username, password, session_vars):
    pwd = f"#PWD_INSTAGRAM:0:{int(time.time())}:{password}"
    url = "https://i.instagram.com/api/v1/bloks/apps/com.bloks.www.bloks.caa.login.async.send_login_request/"

    payload = {
        "params": json.dumps({
            "client_input_params": {
                "sim_phones": [], "aymh_accounts": [], "secure_family_device_id": "",
                "has_granted_read_contacts_permissions": 0, "auth_secure_device_id": "",
                "has_whatsapp_installed": 1, "password": pwd, "event_flow": "login_manual",
                "password_contains_non_ascii": "false", "device_id": session_vars["device_id"],
                "login_attempt_count": 1, "machine_id": "", "accounts_list": [],
                "family_device_id": session_vars["family_device_id"], "fb_ig_device_id": [],
                "device_emails": [], "try_num": 1, "lois_settings": {"lois_token": ""},
                "event_step": "home_page", "contact_point": username
            },
            "server_params": {
                "login_credential_type": "none", "server_login_source": "login",
                "waterfall_id": session_vars["waterfall_id"], "two_step_login_type": "one_step_login",
                "login_source": "Login", "is_platform_login": 0,
                "INTERNALlatency_qpl_marker_id": 36707139, "qe_device_id": session_vars["qe_device_id"],
                "username_text_input_id": "lz1ed6:129", "password_text_input_id": "lz1ed6:130",
                "device_id": session_vars["device_id"],
                "INTERNALlatency_qpl_instance_id": random.random()*1e14,
                "reg_flow_source": "lid_landing_screen", "credential_type": "password",
                "caller": "gslr", "family_device_id": session_vars["family_device_id"],
                "access_flow_version": "pre_mt_behavior"
            }
        }),
        "bk_client_context": json.dumps({
            "bloks_version": session_vars["bloks_version"], "styles_id": "instagram"
        }),
        "bloks_versioning_id": session_vars["bloks_version"]
    }

    headers = {
        "User-Agent": "Instagram 275.0.0.27.98 Android (29/10; 443dpi; 1080x2224; HUAWEI; STK-L21; HWSTK-HF; kirin710; en_OM; 458229237)",
        "x-ig-app-locale": "en_OM", "x-ig-device-locale": "en_OM", "x-ig-mapped-locale": "en_AR",
        "x-pigeon-session-id": session_vars["pigeon_session_id"],
        "x-pigeon-rawclienttime": session_vars["rawclienttime"],
        "x-ig-bandwidth-speed-kbps": session_vars["bandwidth_speed"],
        "x-ig-bandwidth-totalbytes-b": session_vars["bandwidth_totalbytes"],
        "x-ig-bandwidth-totaltime-ms": session_vars["bandwidth_totaltime"],
        "x-bloks-version-id": session_vars["bloks_version"],
        "x-ig-device-id": session_vars["qe_device_id"],
        "x-ig-family-device-id": session_vars["family_device_id"],
        "x-ig-android-id": session_vars["device_id"], "x-ig-timezone-offset": "14400",
        "x-fb-connection-type": "WIFI", "x-ig-connection-type": "WIFI",
        "x-ig-capabilities": "3brTv10=", "x-ig-app-id": "567067343352427",
        "priority": "u=3", "accept-language": "en-OM, en-US",
        "x-mid": session_vars["machine_id"], "ig-intended-user-id": "0",
        "x-fb-http-engine": "Liger", "x-fb-client-ip": "True", "x-fb-server-cluster": "True"
    }
    
    response = requests.post(url, data=payload, headers=headers)
    return response.text, response.headers.get('ig-set-x-mid')

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [['تسجيل دخول Instagram']]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    await update.message.reply_text(
        'مرحبا بك في بوت تسجيل الدخول لـ Instagram',
        reply_markup=reply_markup
    )
    return USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.text == 'تسجيل دخول Instagram':
        await update.message.reply_text(
            'ادخل اسم المستخدم',
            reply_markup=ReplyKeyboardRemove()
        )
        return USERNAME
    
    user_id = update.effective_user.id
    username = update.message.text
    
    if user_id not in user_sessions:
        user_sessions[user_id] = {'session_vars': generate_ids()}
    
    user_sessions[user_id]['username'] = username
    
    await update.message.reply_text('ادخل كلمة المرور')
    return PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    password = update.message.text
    
    username = user_sessions[user_id]['username']
    session_vars = user_sessions[user_id]['session_vars']
    
    await update.message.reply_text('جاري تسجيل الدخول...')
    
    try:
        response, mid = login(username, password, session_vars)
        user_sessions[user_id]['mid'] = mid
        
        if 'IG-Set-Authorization' in response:
            match = ree.search(r'IG-Set-Authorization.*?Bearer ([A-Za-z0-9:_=\-]+)', response)
            if match:
                token = match.group(1)
                ssid = extract_session_from_token(token)
                await update.message.reply_text(
                    f'تم تسجيل الدخول بنجاح\n\n'
                    f'API SSID: {ssid}\n'
                    f'X-MID: {mid}'
                )
                return ConversationHandler.END
                
        elif 'The password you entered is incorrect.' in response:
            keyboard = [['اعادة تعيين كلمة المرور'], ['الغاء']]
            reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            await update.message.reply_text(
                'كلمة المرور غير صحيحة',
                reply_markup=reply_markup
            )
            return ConversationHandler.END
            
        elif "two_step_verification_context" in response:
            response = response.replace('\\', '').replace('\\\\', '').replace('\\\\\\', '')
            two_step_context = response.split('"INTERNAL_INFRA_screen_id"), (bk.action.array.Make, "')[1].split('", "two_factor_login')[0]
            user_sessions[user_id]['two_step_context'] = two_step_context
            
            keyboard = [
                ['قبول التسجيل من جهاز اخر'],
                ['استخدام رموز النسخ الاحتياطي'],
                ['رمز SMS'],
                ['رمز WhatsApp'],
                ['تطبيق المصادقة']
            ]
            reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
            await update.message.reply_text(
                'مطلوب التحقق بخطوتين\nاختر طريقة التحقق',
                reply_markup=reply_markup
            )
            return TWO_FA_METHOD
            
        elif "challenge_context" in response:
            response_clean = response.replace('\\', '').replace('\\\\', '').replace('\\\\\\', '')
            api_path = ree.search(r'"api_path"\s*:\s*"([^"]+)"', response_clean).group(1)
            challenge_context = ree.search(r'"challenge_context"\s*:\s*"([^"]+)"', response_clean).group(1)
            
            user_sessions[user_id]['api_path'] = api_path
            user_sessions[user_id]['challenge_context'] = challenge_context
            
            await update.message.reply_text('جاري فتح صفحة التحقق...')
            
            # Get verification methods
            guid = session_vars["qe_device_id"]
            device_id = session_vars["device_id"]
            url = f"https://i.instagram.com/api/v1{api_path}?guid={guid}&device_id={device_id}&challenge_context={challenge_context}"
            headers = {
                'User-Agent': 'Instagram 275.0.0.27.98 Android (29/10; 443dpi; 1080x2224; HUAWEI; STK-L21; HWSTK-HF; kirin710; en_OM; 458229237)',
                'X-Bloks-Version-Id': session_vars["bloks_version"],
                'X-Mid': mid,
            }
            
            r = requests.get(url, headers=headers)
            
            if 'select_verify_method' in r.text:
                response_json = r.json()
                user_sessions[user_id]['challenge_context'] = response_json["challenge_context"]
                user_sessions[user_id]['nonce_code'] = response_json["nonce_code"]
                user_sessions[user_id]['cni'] = response_json["cni"]
                method = response_json["step_data"]
                
                buttons = []
                if "email" in method:
                    buttons.append([f'البريد: {method["email"]}'])
                if "phone_number" in method:
                    buttons.append([f'الهاتف: {method["phone_number"]}'])
                
                reply_markup = ReplyKeyboardMarkup(buttons, resize_keyboard=True)
                await update.message.reply_text(
                    'اختر طريقة التحقق',
                    reply_markup=reply_markup
                )
                return VERIFY_METHOD
            else:
                await update.message.reply_text('فشل فتح صفحة التحقق')
                return ConversationHandler.END
        else:
            await update.message.reply_text('حدث خطأ غير متوقع')
            return ConversationHandler.END
            
    except Exception as e:
        await update.message.reply_text(f'حدث خطأ: {str(e)}')
        return ConversationHandler.END

async def handle_verify_method(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    choice = '0' if 'البريد' in update.message.text else '1'
    
    user_sessions[user_id]['verify_choice'] = choice
    
    await update.message.reply_text('ادخل الرمز المرسل', reply_markup=ReplyKeyboardRemove())
    return VERIFY_CODE

async def handle_verify_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    code = update.message.text
    
    # Implementation for verification code submission
    await update.message.reply_text('جاري التحقق من الرمز...')
    
    # Add verification logic here
    
    return ConversationHandler.END

async def handle_2fa_method(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    method = update.message.text
    
    if 'رمز SMS' in method or 'رمز WhatsApp' in method:
        await update.message.reply_text(
            'ادخل الرمز المرسل',
            reply_markup=ReplyKeyboardRemove()
        )
        user_sessions[user_id]['2fa_method'] = 'sms' if 'SMS' in method else 'whatsapp'
        return TWO_FA_CODE
    
    elif 'تطبيق المصادقة' in method:
        await update.message.reply_text(
            'ادخل الرمز من تطبيق المصادقة',
            reply_markup=ReplyKeyboardRemove()
        )
        user_sessions[user_id]['2fa_method'] = 'totp'
        return TWO_FA_CODE
        
    elif 'رموز النسخ الاحتياطي' in method:
        await update.message.reply_text(
            'ادخل رمز النسخ الاحتياطي',
            reply_markup=ReplyKeyboardRemove()
        )
        user_sessions[user_id]['2fa_method'] = 'backup'
        return TWO_FA_CODE

async def handle_2fa_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    code = update.message.text
    
    await update.message.reply_text('جاري التحقق...')
    
    # Add 2FA verification logic here
    
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        'تم الغاء العملية',
        reply_markup=ReplyKeyboardRemove()
    )
    return ConversationHandler.END

def main():
    TOKEN = "8458197969:AAHF0VtddPdgxVAGkQhAFYAgNSPwsIZV9sg"
    
    application = Application.builder().token(TOKEN).build()
    
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            VERIFY_METHOD: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_verify_method)],
            VERIFY_CODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_verify_code)],
            TWO_FA_METHOD: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_2fa_method)],
            TWO_FA_CODE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_2fa_code)],
        },
        fallbacks=[MessageHandler(filters.Regex('^الغاء$'), cancel)],
    )
    
    application.add_handler(conv_handler)
    
    print('البوت يعمل الان...')
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
