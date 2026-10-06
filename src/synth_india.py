import os, random
import pandas as pd

# Template-based synthetic India scam + benign messages in en / hinglish / hi / kn.
# Patterns follow public advisories (I4C, PIB fact-checks, DoT, bank warnings). Every row is is_synthetic=True;
# build_text.py splits on template_family so variants (and translations) of one template never straddle train/test.
random.seed(0)
N_PER_TEMPLATE = 15

SLOTS = {
    "name": ["Rahul", "Priya", "Suresh", "Anjali", "Manjunath", "Kavya", "Imran", "Deepa", "Arjun", "Lakshmi"],
    "amt": ["4,999", "12,500", "1,25,000", "49,000", "2,500", "75,000", "9,999"],
    "case": ["CBI/2026/{n}", "MH-CYB-{n}", "NCB/DL/{n}", "ED/PMLA/{n}"],
    "parcel": ["FDX{n}", "DHL{n}IN", "BLR{n}", "EM{n}IN"],
    "otp": ["{n4}", "{n6}"],
    "bank": ["SBI", "HDFC", "ICICI", "Axis", "Canara", "Kotak"],
    "url": ["sbi-kyc-update.in/verify", "bit.ly/3xKyc{n4}", "indiapost-redeliver.top/p", "hdfc-netbank-secure.co/login",
            "rewards-paytm.vip/claim", "echallan-parivahan.cc/pay"],
    "phone": ["+91 9{n9}", "+91 8{n9}", "+92 3{n9}"],
    "city": ["Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Chennai", "Kolkata"],
    "company": ["Amazon", "Flipkart", "Zomato", "Swiggy", "Infosys", "TCS"],
    "date": ["12-10-2026", "15-10-2026", "20-10-2026", "31-10-2026"],
}

def fill(t):
    out = t
    for k, vals in SLOTS.items():
        while "{" + k + "}" in out:
            out = out.replace("{" + k + "}", random.choice(vals), 1)
    for k, digits in (("{n4}", 4), ("{n6}", 6), ("{n9}", 9), ("{n}", 6)):
        while k in out:
            out = out.replace(k, "".join(random.choice("0123456789") for _ in range(digits)), 1)
    return out

# (category, label, channel, {lang: [templates]})
T = [
    ("digital_arrest", 1, "call", {
        "en": ["This is Inspector {name} from {case}. A parcel in your name with illegal drugs was seized in {city}. You are under digital arrest. Stay on video call and do not tell anyone.",
               "Your Aadhaar is linked to a money laundering case {case}. Transfer Rs {amt} to the RBI verification account for clearance or a warrant will be issued today."],
        "hinglish": ["Main CBI officer {name} bol raha hoon, case {case}. Aapke Aadhaar se money laundering hua hai. Aap digital arrest mein hain, video call band mat karna aur kisi ko mat batana.",
                     "Aapke naam ka parcel {city} customs mein pakda gaya hai, usme drugs mile hain. Clearance ke liye Rs {amt} abhi transfer karo warna arrest warrant nikal jayega."],
        "hi": ["मैं सीबीआई अधिकारी {name} बोल रहा हूँ, केस {case}। आपके आधार से मनी लॉन्ड्रिंग हुई है। आप डिजिटल अरेस्ट में हैं, वीडियो कॉल बंद न करें।",
               "आपके नाम का पार्सल {city} कस्टम्स में पकड़ा गया है। जाँच से बचने के लिए तुरंत Rs {amt} ट्रांसफर करें वरना गिरफ्तारी वारंट जारी होगा।"],
        "kn": ["ನಾನು ಸಿಬಿಐ ಅಧಿಕಾರಿ {name}, ಕೇಸ್ {case}. ನಿಮ್ಮ ಆಧಾರ್ ಹಣ ವರ್ಗಾವಣೆ ಪ್ರಕರಣದಲ್ಲಿದೆ. ನೀವು ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್‌ನಲ್ಲಿದ್ದೀರಿ, ವಿಡಿಯೋ ಕಾಲ್ ಕಟ್ ಮಾಡಬೇಡಿ.",
               "ನಿಮ್ಮ ಹೆಸರಿನ ಪಾರ್ಸೆಲ್ {city} ಕಸ್ಟಮ್ಸ್‌ನಲ್ಲಿ ಸಿಕ್ಕಿದೆ. ಬಂಧನ ತಪ್ಪಿಸಲು ಈಗಲೇ Rs {amt} ವರ್ಗಾಯಿಸಿ."]}),
    ("digital_arrest", 0, "sms", {
        "en": ["Alert from I4C: Police or CBI never conduct 'digital arrest' over video call. Report such calls at 1930 or cybercrime.gov.in.",
               "Dear customer, government agencies never ask for money transfers to clear a case. Call 1930 if anyone threatens you on a video call."],
        "hinglish": ["Savdhan: Police ya CBI kabhi video call pe 'digital arrest' nahi karti. Aise call ki shikayat 1930 pe karein.",
                     "Koi bhi sarkari agency case clear karne ke liye paise nahi maangti. Dhamki wali call aaye to 1930 dial karein."],
        "hi": ["सावधान: पुलिस या सीबीआई कभी वीडियो कॉल पर 'डिजिटल अरेस्ट' नहीं करती। ऐसी कॉल की शिकायत 1930 पर करें।"],
        "kn": ["ಎಚ್ಚರಿಕೆ: ಪೊಲೀಸ್ ಅಥವಾ ಸಿಬಿಐ ವಿಡಿಯೋ ಕಾಲ್‌ನಲ್ಲಿ 'ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್' ಮಾಡುವುದಿಲ್ಲ. ಇಂತಹ ಕರೆಗಳನ್ನು 1930ಗೆ ವರದಿ ಮಾಡಿ."]}),
    ("courier_customs", 1, "sms", {
        "en": ["India Post: Your parcel {parcel} is held at the warehouse due to an incomplete address. Update within 24 hrs: {url}",
               "FedEx: Parcel {parcel} contains prohibited items and is held by customs. Press 1 to speak to the officer or pay Rs {amt} penalty."],
        "hinglish": ["India Post: Aapka parcel {parcel} address galat hone ki wajah se ruka hai. 24 ghante mein update karein: {url}",
                     "Aapke parcel {parcel} mein illegal saman mila hai, customs ne roka hai. Officer se baat karne ke liye 1 dabayein."],
        "hi": ["इंडिया पोस्ट: आपका पार्सल {parcel} अधूरे पते के कारण रुका है। 24 घंटे में अपडेट करें: {url}"],
        "kn": ["ಇಂಡಿಯಾ ಪೋಸ್ಟ್: ನಿಮ್ಮ ಪಾರ್ಸೆಲ್ {parcel} ವಿಳಾಸ ಅಪೂರ್ಣವಾಗಿರುವುದರಿಂದ ತಡೆಹಿಡಿಯಲಾಗಿದೆ. 24 ಗಂಟೆಯೊಳಗೆ ಅಪ್‌ಡೇಟ್ ಮಾಡಿ: {url}"]}),
    ("courier_customs", 0, "sms", {
        "en": ["Your India Post article {parcel} has been delivered on {date}. Track at indiapost.gov.in",
               "Your {company} order is out for delivery today. Share OTP {otp} with the delivery agent only at the doorstep."],
        "hinglish": ["Aapka {company} order aaj deliver hoga. OTP {otp} sirf delivery agent ko darwaze par dein.",
                     "Parcel {parcel} {date} ko deliver ho gaya. Track karein indiapost.gov.in par."],
        "hi": ["आपका {company} ऑर्डर आज डिलीवर होगा। OTP {otp} केवल डिलीवरी एजेंट को दें।"],
        "kn": ["ನಿಮ್ಮ {company} ಆರ್ಡರ್ ಇಂದು ಡೆಲಿವರಿ ಆಗಲಿದೆ. OTP {otp} ಅನ್ನು ಡೆಲಿವರಿ ಏಜೆಂಟ್‌ಗೆ ಮಾತ್ರ ನೀಡಿ."]}),
    ("kyc", 1, "sms", {
        "en": ["Dear {bank} customer, your account will be blocked today due to pending KYC. Update PAN immediately: {url}",
               "Your {bank} YONO account is suspended. Click {url} and enter your details to reactivate."],
        "hinglish": ["Dear {bank} customer, aapka KYC pending hai, aaj account block ho jayega. Turant PAN update karein: {url}",
                     "Aapka {bank} account suspend ho gaya hai. Reactivate karne ke liye {url} pe details bharein."],
        "hi": ["प्रिय {bank} ग्राहक, KYC लंबित होने के कारण आपका खाता आज बंद हो जाएगा। तुरंत PAN अपडेट करें: {url}"],
        "kn": ["ಪ್ರಿಯ {bank} ಗ್ರಾಹಕರೇ, KYC ಬಾಕಿ ಇರುವುದರಿಂದ ನಿಮ್ಮ ಖಾತೆ ಇಂದು ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ. ತಕ್ಷಣ PAN ಅಪ್‌ಡೇಟ್ ಮಾಡಿ: {url}"]}),
    ("kyc", 0, "sms", {
        "en": ["{bank}: Your KYC is due for periodic update. Visit your home branch or use the official app. We never send KYC links by SMS.",
               "{bank}: Your Re-KYC has been completed successfully on {date}. No further action is needed."],
        "hinglish": ["{bank}: Aapka KYC update due hai. Branch jaayein ya official app use karein. Hum SMS par link nahi bhejte."],
        "hi": ["{bank}: आपका KYC अपडेट देय है। शाखा जाएँ या आधिकारिक ऐप का उपयोग करें। हम SMS से लिंक नहीं भेजते।"],
        "kn": ["{bank}: ನಿಮ್ಮ KYC ಅಪ್‌ಡೇಟ್ ಬಾಕಿಯಿದೆ. ಶಾಖೆಗೆ ಭೇಟಿ ನೀಡಿ ಅಥವಾ ಅಧಿಕೃತ ಆ್ಯಪ್ ಬಳಸಿ. ನಾವು SMS ಮೂಲಕ ಲಿಂಕ್ ಕಳುಹಿಸುವುದಿಲ್ಲ."]}),
    ("upi", 1, "whatsapp", {
        "en": ["Rs {amt} has been credited to your account by mistake. Please approve the UPI collect request to return it. Urgent!",
               "Congratulations! You won Rs {amt} cashback. Enter your UPI PIN to receive the money: {url}"],
        "hinglish": ["Galti se aapke account mein Rs {amt} aa gaye hain. Please UPI request approve karke wapas kar dijiye, urgent hai.",
                     "Badhai ho! Aapko Rs {amt} cashback mila hai. Paise lene ke liye UPI PIN daalein: {url}"],
        "hi": ["गलती से आपके खाते में Rs {amt} आ गए हैं। कृपया UPI रिक्वेस्ट अप्रूव करके वापस करें।"],
        "kn": ["ತಪ್ಪಾಗಿ ನಿಮ್ಮ ಖಾತೆಗೆ Rs {amt} ಬಂದಿದೆ. ದಯವಿಟ್ಟು UPI ರಿಕ್ವೆಸ್ಟ್ ಅಪ್ರೂವ್ ಮಾಡಿ ಹಿಂದಿರುಗಿಸಿ."]}),
    ("upi", 0, "sms", {
        "en": ["Rs {amt} credited to your {bank} a/c via UPI from {name} on {date}. Not you? Call your bank.",
               "You have received a UPI collect request of Rs {amt} from {name}. Entering your PIN will DEBIT your account."],
        "hinglish": ["{name} se Rs {amt} UPI ke through aapke {bank} account mein aaye, {date}."],
        "hi": ["{name} से Rs {amt} UPI द्वारा आपके {bank} खाते में जमा, {date}।"],
        "kn": ["{name} ಅವರಿಂದ Rs {amt} UPI ಮೂಲಕ ನಿಮ್ಮ {bank} ಖಾತೆಗೆ ಜಮೆಯಾಗಿದೆ, {date}."]}),
    ("bank", 1, "sms", {
        "en": ["{bank}: Rs {amt} debit attempted from your card. If not you, share the OTP {otp} with our officer on {phone} to cancel.",
               "Your {bank} credit card reward points worth Rs {amt} expire today. Redeem now: {url}"],
        "hinglish": ["{bank}: Aapke card se Rs {amt} kat rahe hain. Cancel karne ke liye OTP {otp} officer ko batayein {phone} par.",
                     "Aapke {bank} reward points Rs {amt} aaj expire ho rahe hain. Abhi redeem karein: {url}"],
        "hi": ["{bank}: आपके कार्ड से Rs {amt} कट रहे हैं। रद्द करने के लिए OTP {otp} {phone} पर अधिकारी को बताएं।"],
        "kn": ["{bank}: ನಿಮ್ಮ ಕಾರ್ಡ್‌ನಿಂದ Rs {amt} ಕಡಿತವಾಗುತ್ತಿದೆ. ರದ್ದುಗೊಳಿಸಲು OTP {otp} ಅನ್ನು {phone} ಗೆ ತಿಳಿಸಿ."]}),
    ("bank", 0, "sms", {
        "en": ["{otp} is your OTP for txn of Rs {amt} at {company}. Do not share it with anyone, {bank} never asks for OTP.",
               "{bank}: Rs {amt} debited from a/c XX{n4} on {date}. Avl bal updated. Not you? Call the number on your card."],
        "hinglish": ["{otp} aapka OTP hai Rs {amt} ke liye. Kisi ko na batayein, {bank} kabhi OTP nahi maangta."],
        "hi": ["{otp} आपका OTP है Rs {amt} के लेनदेन के लिए। किसी से साझा न करें, {bank} कभी OTP नहीं मांगता।"],
        "kn": ["{otp} ಇದು Rs {amt} ವಹಿವಾಟಿಗೆ ನಿಮ್ಮ OTP. ಯಾರೊಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ, {bank} ಎಂದಿಗೂ OTP ಕೇಳುವುದಿಲ್ಲ."]}),
    ("job", 1, "whatsapp", {
        "en": ["Hi, I am {name} from {company} HR. Part-time job: like YouTube videos and earn Rs {amt} daily. Pay Rs 999 registration to start.",
               "You are selected for a work-from-home data entry job at {company}. Salary Rs {amt}/month. Pay security deposit to confirm: {url}"],
        "hinglish": ["Hello, main {company} HR se {name}. Part time job hai, YouTube videos like karo aur roz Rs {amt} kamao. Shuru karne ke liye Rs 999 registration.",
                     "Aapka {company} work from home job mein selection hua hai. Salary Rs {amt}. Confirm karne ke liye deposit bharein: {url}"],
        "hi": ["नमस्ते, मैं {company} HR से {name}। पार्ट टाइम जॉब: वीडियो लाइक करें और रोज़ Rs {amt} कमाएँ। शुरू करने के लिए Rs 999 पंजीकरण।"],
        "kn": ["ನಮಸ್ಕಾರ, ನಾನು {company} HR ನಿಂದ {name}. ಪಾರ್ಟ್ ಟೈಮ್ ಕೆಲಸ: ವಿಡಿಯೋ ಲೈಕ್ ಮಾಡಿ ದಿನಕ್ಕೆ Rs {amt} ಗಳಿಸಿ. ಪ್ರಾರಂಭಿಸಲು Rs 999 ನೋಂದಣಿ."]}),
    ("job", 0, "email", {
        "en": ["Hi {name}, thank you for applying to {company}. Your interview is scheduled on {date} in {city}. We never charge candidates any fee.",
               "{company} Careers: Your application has been received. Track status on our official careers portal."],
        "hinglish": ["Hi {name}, {company} mein apply karne ke liye thanks. Aapka interview {date} ko {city} mein hai. Hum koi fee nahi lete."],
        "hi": ["नमस्ते {name}, {company} में आवेदन के लिए धन्यवाद। आपका इंटरव्यू {date} को {city} में है। हम कोई शुल्क नहीं लेते।"],
        "kn": ["ನಮಸ್ಕಾರ {name}, {company} ಗೆ ಅರ್ಜಿ ಸಲ್ಲಿಸಿದ್ದಕ್ಕೆ ಧನ್ಯವಾದ. ನಿಮ್ಮ ಸಂದರ್ಶನ {date} ರಂದು {city} ನಲ್ಲಿ. ನಾವು ಯಾವುದೇ ಶುಲ್ಕ ಪಡೆಯುವುದಿಲ್ಲ."]}),
    ("lottery", 1, "whatsapp", {
        "en": ["KBC Lottery: Your number won Rs 25,00,000! Contact manager {name} on {phone} and pay Rs {amt} processing fee to claim.",
               "Congratulations! Your SIM was selected in the {company} lucky draw. Claim your prize at {url}"],
        "hinglish": ["KBC lottery: Aapka number Rs 25 lakh jeeta hai! Manager {name} se {phone} par sampark karein, Rs {amt} processing fee bharein.",
                     "Badhai ho! {company} lucky draw mein aapka SIM select hua hai. Inaam yahan claim karein: {url}"],
        "hi": ["KBC लॉटरी: आपके नंबर ने Rs 25 लाख जीते हैं! मैनेजर {name} से {phone} पर संपर्क करें और Rs {amt} प्रोसेसिंग फीस भरें।"],
        "kn": ["KBC ಲಾಟರಿ: ನಿಮ್ಮ ನಂಬರ್ Rs 25 ಲಕ್ಷ ಗೆದ್ದಿದೆ! ಮ್ಯಾನೇಜರ್ {name} ಅವರನ್ನು {phone} ನಲ್ಲಿ ಸಂಪರ್ಕಿಸಿ, Rs {amt} ಶುಲ್ಕ ಪಾವತಿಸಿ."]}),
    ("lottery", 0, "sms", {
        "en": ["{company}: You earned a scratch card worth Rs 25 in the app. Open the app to view. No payment is ever required.",
               "Thanks for shopping at {company}! You got {amt} SuperCoins, visible in your account."],
        "hinglish": ["{company} app mein aapko Rs 25 ka scratch card mila hai. App kholkar dekhein, koi payment nahi lagta."],
        "hi": ["{company} ऐप में आपको Rs 25 का स्क्रैच कार्ड मिला है। ऐप खोलकर देखें।"],
        "kn": ["{company} ಆ್ಯಪ್‌ನಲ್ಲಿ ನಿಮಗೆ Rs 25 ಸ್ಕ್ರ್ಯಾಚ್ ಕಾರ್ಡ್ ಸಿಕ್ಕಿದೆ. ಆ್ಯಪ್ ತೆರೆದು ನೋಡಿ."]}),
    ("echallan", 1, "sms", {
        "en": ["Your vehicle has a pending e-challan of Rs {amt}. Pay today to avoid court action: {url}"],
        "hinglish": ["Aapki gaadi ka Rs {amt} ka e-challan pending hai. Court case se bachne ke liye aaj pay karein: {url}"],
        "hi": ["आपके वाहन का Rs {amt} का ई-चालान लंबित है। कोर्ट कार्रवाई से बचने के लिए आज भुगतान करें: {url}"],
        "kn": ["ನಿಮ್ಮ ವಾಹನದ Rs {amt} ಇ-ಚಲನ್ ಬಾಕಿ ಇದೆ. ಕೋರ್ಟ್ ಕ್ರಮ ತಪ್ಪಿಸಲು ಇಂದೇ ಪಾವತಿಸಿ: {url}"]}),
    ("echallan", 0, "sms", {
        "en": ["e-Challan issued for your vehicle on {date}. View and pay only at echallan.parivahan.gov.in"],
        "hinglish": ["Aapki gaadi ka e-challan {date} ko bana hai. Sirf echallan.parivahan.gov.in par dekhein aur pay karein."],
        "hi": ["आपके वाहन का ई-चालान {date} को जारी हुआ है। केवल echallan.parivahan.gov.in पर देखें।"],
        "kn": ["ನಿಮ್ಮ ವಾಹನಕ್ಕೆ {date} ರಂದು ಇ-ಚಲನ್ ನೀಡಲಾಗಿದೆ. echallan.parivahan.gov.in ನಲ್ಲಿ ಮಾತ್ರ ನೋಡಿ."]}),
]

# Second templates for cells that had only one, so build_text.py can put one template per
# (category, label, language) cell in test and the other in train.
EXTRA = {
    ("bank", 0): {
        "hinglish": ["{bank}: Rs {amt} aapke a/c XX{n4} se {date} ko debit hue. Aapne nahi kiya? Card ke peeche diye number par call karein."],
        "hi": ["{bank}: खाता XX{n4} से {date} को Rs {amt} डेबिट हुए। आपने नहीं किया? कार्ड के पीछे दिए नंबर पर कॉल करें।"],
        "kn": ["{bank}: ಖಾತೆ XX{n4} ನಿಂದ {date} ರಂದು Rs {amt} ಡೆಬಿಟ್ ಆಗಿದೆ. ನೀವು ಮಾಡಿಲ್ಲವೇ? ಕಾರ್ಡ್ ಹಿಂದಿನ ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡಿ."]},
    ("bank", 1): {
        "hi": ["आपके {bank} रिवॉर्ड पॉइंट्स Rs {amt} आज समाप्त हो रहे हैं। अभी रिडीम करें: {url}"],
        "kn": ["ನಿಮ್ಮ {bank} ರಿವಾರ್ಡ್ ಪಾಯಿಂಟ್ಸ್ Rs {amt} ಇಂದು ಮುಕ್ತಾಯವಾಗುತ್ತವೆ. ಈಗಲೇ ರಿಡೀಮ್ ಮಾಡಿ: {url}"]},
    ("courier_customs", 0): {
        "hi": ["आपका इंडिया पोस्ट आर्टिकल {parcel} {date} को डिलीवर हो गया है। indiapost.gov.in पर ट्रैक करें।"],
        "kn": ["ನಿಮ್ಮ ಇಂಡಿಯಾ ಪೋಸ್ಟ್ ಪಾರ್ಸೆಲ್ {parcel} {date} ರಂದು ಡೆಲಿವರಿ ಆಗಿದೆ. indiapost.gov.in ನಲ್ಲಿ ಟ್ರ್ಯಾಕ್ ಮಾಡಿ."]},
    ("courier_customs", 1): {
        "hi": ["आपके पार्सल {parcel} में प्रतिबंधित सामान मिला है, कस्टम्स ने रोका है। अधिकारी से बात करने के लिए 1 दबाएँ।"],
        "kn": ["ನಿಮ್ಮ ಪಾರ್ಸೆಲ್ {parcel} ನಲ್ಲಿ ನಿಷೇಧಿತ ವಸ್ತುಗಳಿವೆ, ಕಸ್ಟಮ್ಸ್ ತಡೆಹಿಡಿದಿದೆ. ಅಧಿಕಾರಿಯೊಂದಿಗೆ ಮಾತನಾಡಲು 1 ಒತ್ತಿ."]},
    ("digital_arrest", 0): {
        "hi": ["कोई भी सरकारी एजेंसी केस निपटाने के लिए पैसे नहीं मांगती। धमकी भरी कॉल आए तो 1930 पर कॉल करें।"],
        "kn": ["ಯಾವುದೇ ಸರ್ಕಾರಿ ಸಂಸ್ಥೆ ಪ್ರಕರಣ ಮುಗಿಸಲು ಹಣ ಕೇಳುವುದಿಲ್ಲ. ಬೆದರಿಕೆ ಕರೆ ಬಂದರೆ 1930ಗೆ ಕರೆ ಮಾಡಿ."]},
    ("echallan", 0): {
        "en": ["Your traffic challan for vehicle reg. on {date} has been paid successfully. Receipt available at echallan.parivahan.gov.in"],
        "hinglish": ["Aapka e-challan {date} ko successfully pay ho gaya. Receipt echallan.parivahan.gov.in par dekhein."],
        "hi": ["आपका ई-चालान {date} को सफलतापूर्वक भुगतान हो गया। रसीद echallan.parivahan.gov.in पर देखें।"],
        "kn": ["ನಿಮ್ಮ ಇ-ಚಲನ್ {date} ರಂದು ಯಶಸ್ವಿಯಾಗಿ ಪಾವತಿಯಾಗಿದೆ. ರಸೀದಿ echallan.parivahan.gov.in ನಲ್ಲಿ ಲಭ್ಯ."]},
    ("echallan", 1): {
        "en": ["Final notice: traffic violation fine Rs {amt} unpaid. Your driving licence will be suspended. Pay now: {url}"],
        "hinglish": ["Final notice: Rs {amt} traffic fine baaki hai, aapka licence suspend ho jayega. Abhi pay karein: {url}"],
        "hi": ["अंतिम सूचना: Rs {amt} ट्रैफिक जुर्माना बाकी है, आपका लाइसेंस निलंबित होगा। अभी भुगतान करें: {url}"],
        "kn": ["ಕೊನೆಯ ಸೂಚನೆ: Rs {amt} ಟ್ರಾಫಿಕ್ ದಂಡ ಬಾಕಿಯಿದೆ, ನಿಮ್ಮ ಲೈಸೆನ್ಸ್ ಅಮಾನತು ಆಗುತ್ತದೆ. ಈಗಲೇ ಪಾವತಿಸಿ: {url}"]},
    ("job", 0): {
        "hinglish": ["{company} Careers: Aapki application mil gayi hai. Status official careers portal par check karein."],
        "hi": ["{company} करियर: आपका आवेदन प्राप्त हो गया है। स्थिति आधिकारिक करियर पोर्टल पर देखें।"],
        "kn": ["{company} ಕರಿಯರ್ಸ್: ನಿಮ್ಮ ಅರ್ಜಿ ಸ್ವೀಕರಿಸಲಾಗಿದೆ. ಸ್ಥಿತಿಯನ್ನು ಅಧಿಕೃತ ಕರಿಯರ್ ಪೋರ್ಟಲ್‌ನಲ್ಲಿ ನೋಡಿ."]},
    ("job", 1): {
        "hi": ["{company} में वर्क फ्रॉम होम जॉब के लिए आपका चयन हुआ है। वेतन Rs {amt}। पुष्टि के लिए जमा राशि भरें: {url}"],
        "kn": ["{company} ವರ್ಕ್ ಫ್ರಮ್ ಹೋಮ್ ಕೆಲಸಕ್ಕೆ ನೀವು ಆಯ್ಕೆಯಾಗಿದ್ದೀರಿ. ಸಂಬಳ Rs {amt}. ಖಚಿತಪಡಿಸಲು ಠೇವಣಿ ಪಾವತಿಸಿ: {url}"]},
    ("kyc", 0): {
        "hinglish": ["{bank}: Aapka Re-KYC {date} ko complete ho gaya hai. Aur kuch karne ki zarurat nahi."],
        "hi": ["{bank}: आपका री-KYC {date} को सफलतापूर्वक पूरा हो गया है। आगे कुछ करने की आवश्यकता नहीं है।"],
        "kn": ["{bank}: ನಿಮ್ಮ ರೀ-KYC {date} ರಂದು ಯಶಸ್ವಿಯಾಗಿ ಪೂರ್ಣಗೊಂಡಿದೆ. ಮುಂದೆ ಏನೂ ಮಾಡಬೇಕಿಲ್ಲ."]},
    ("kyc", 1): {
        "hi": ["आपका {bank} खाता निलंबित कर दिया गया है। दोबारा चालू करने के लिए {url} पर विवरण भरें।"],
        "kn": ["ನಿಮ್ಮ {bank} ಖಾತೆಯನ್ನು ಅಮಾನತುಗೊಳಿಸಲಾಗಿದೆ. ಮರು ಸಕ್ರಿಯಗೊಳಿಸಲು {url} ನಲ್ಲಿ ವಿವರ ನೀಡಿ."]},
    ("lottery", 0): {
        "hinglish": ["{company} par shopping ke liye thanks! Aapko {amt} SuperCoins mile hain, account mein dikh rahe hain."],
        "hi": ["{company} पर खरीदारी के लिए धन्यवाद! आपको {amt} सुपरकॉइन्स मिले हैं, जो आपके खाते में दिख रहे हैं।"],
        "kn": ["{company} ನಲ್ಲಿ ಖರೀದಿಸಿದ್ದಕ್ಕೆ ಧನ್ಯವಾದ! ನಿಮಗೆ {amt} ಸೂಪರ್‌ಕಾಯಿನ್ಸ್ ಸಿಕ್ಕಿವೆ, ಖಾತೆಯಲ್ಲಿ ಕಾಣುತ್ತವೆ."]},
    ("lottery", 1): {
        "hi": ["बधाई हो! {company} लकी ड्रॉ में आपका सिम चुना गया है। इनाम यहाँ क्लेम करें: {url}"],
        "kn": ["ಅಭಿನಂದನೆಗಳು! {company} ಲಕ್ಕಿ ಡ್ರಾದಲ್ಲಿ ನಿಮ್ಮ ಸಿಮ್ ಆಯ್ಕೆಯಾಗಿದೆ. ಬಹುಮಾನವನ್ನು ಇಲ್ಲಿ ಪಡೆಯಿರಿ: {url}"]},
    ("upi", 0): {
        "hinglish": ["{name} ne aapko Rs {amt} ki UPI collect request bheji hai. PIN daalne se aapke account se paise KATENGE."],
        "hi": ["{name} ने आपको Rs {amt} की UPI कलेक्ट रिक्वेस्ट भेजी है। PIN डालने पर आपके खाते से पैसे कटेंगे।"],
        "kn": ["{name} ಅವರು Rs {amt} UPI ಕಲೆಕ್ಟ್ ರಿಕ್ವೆಸ್ಟ್ ಕಳುಹಿಸಿದ್ದಾರೆ. PIN ಹಾಕಿದರೆ ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಹಣ ಕಡಿತವಾಗುತ್ತದೆ."]},
    ("upi", 1): {
        "hi": ["बधाई हो! आपको Rs {amt} कैशबैक मिला है। पैसे पाने के लिए UPI PIN डालें: {url}"],
        "kn": ["ಅಭಿನಂದನೆಗಳು! ನಿಮಗೆ Rs {amt} ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್ ಸಿಕ್ಕಿದೆ. ಹಣ ಪಡೆಯಲು UPI PIN ಹಾಕಿ: {url}"]},
}
for cat, label, _, by_lang in T:
    for lang, temps in EXTRA.get((cat, label), {}).items():
        by_lang[lang] = by_lang[lang] + temps

# template_family = the same message in all four languages. Templates are translated by position, except in these
# two cells where the English pair is listed in the opposite order to hinglish/hi/kn (checked by reading them side
# by side), so English is flipped to line up. build_text.py splits and clusters on template_family.
EN_REVERSED = {("digital_arrest", 1), ("courier_customs", 0)}

rows = []
for ci, (cat, label, channel, by_lang) in enumerate(T):
    for lang, temps in by_lang.items():
        for ti, t in enumerate(temps):
            tid = f"synth_{cat}_{label}_{lang}_{ci}_{ti}"
            fi = len(temps) - 1 - ti if lang == "en" and (cat, label) in EN_REVERSED else ti
            family = f"synth_{cat}_{label}_{ci}_{fi}"
            seen = set()
            for _ in range(N_PER_TEMPLATE * 3):
                s = fill(t)
                if s not in seen:
                    seen.add(s)
                    rows.append({"text": s, "label": label, "category": cat, "channel": channel,
                                 "language": lang, "template_id": tid, "template_family": family})
                if len(seen) >= N_PER_TEMPLATE:
                    break

df = pd.DataFrame(rows)
fam_langs = df.groupby("template_family")["template_id"].nunique()
assert (fam_langs == 4).all(), "every template family needs exactly one template per language"
df["language"] = df["language"].map({"en": "english", "hi": "hindi", "kn": "kannada", "hinglish": "hinglish"})
os.makedirs("data/external/text/synth_india", exist_ok=True)
df.to_csv("data/external/text/synth_india/synth_india.csv", index=False)
print(df.groupby(["language", "label"]).size().unstack(), "\ntemplates:", df["template_id"].nunique())
