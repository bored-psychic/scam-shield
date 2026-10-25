import type { Evidence } from "../types/report";
import type { HelpLang } from "./helpline";

// The investment-scam rules A1-A12 (src/shield/messages/invest_rules.py, docs/plans/investment_scams.md Phase A): the user-facing reason of each rule
// in English, Hindi and Kannada, and the SEBI advice card. Display only: whether a rule fired is decided by the API (the Report's evidence ids
// `rule.invest_*`); English is what the API sends and tests/test_invest_rules.py I8 and investment.test.ts check that these English strings equal it.
//
// Hindi and Kannada are the model's wording in a formal, professional register and are NOT yet checked by a native speaker (INVEST_NEEDS_REVIEW). Set a
// language to false only after a native speaker has signed it off. (The helpline row's Kannada was checked; these new strings were not.)

export const INVEST_NEEDS_REVIEW: Record<HelpLang, boolean> = { en: false, hi: true, kn: true };

/** The Evidence id prefix of every rule in this file. A Report has the investment card exactly when one of its evidence ids starts with it. */
export const INVEST_PREFIX = "rule.invest_";

export const INVEST_REASONS: Record<string, Record<HelpLang, string>> = {
  "rule.invest_upi": {   // A1
    en: "Asks for investment money to a UPI ID that is not a SEBI @valid ID.",
    hi: "निवेश के लिए धन ऐसी UPI आईडी पर भेजने को कहा गया है जो SEBI की @valid आईडी नहीं है।",
    kn: "ಹೂಡಿಕೆಗಾಗಿ ಹಣವನ್ನು SEBI @valid ಅಲ್ಲದ UPI ಐಡಿಗೆ ಪಾವತಿಸುವಂತೆ ಕೇಳಲಾಗಿದೆ.",
  },
  "rule.invest_sebi_claim": {   // A2
    en: "Claims to be SEBI registered but gives no registration number.",
    hi: "SEBI-पंजीकृत होने का दावा किया गया है, किंतु कोई पंजीकरण संख्या नहीं दी गई।",
    kn: "SEBI ನೋಂದಾಯಿತ ಎಂದು ಹೇಳಿಕೊಳ್ಳಲಾಗಿದೆ, ಆದರೆ ನೋಂದಣಿ ಸಂಖ್ಯೆಯನ್ನು ನೀಡಿಲ್ಲ.",
  },
  "rule.invest_guaranteed": {   // A3
    en: "Promises guaranteed returns. No real investment can guarantee returns.",
    hi: "गारंटीशुदा रिटर्न का वादा किया गया है। कोई भी वास्तविक निवेश रिटर्न की गारंटी नहीं दे सकता।",
    kn: "ಖಚಿತ ಲಾಭದ ಭರವಸೆ ನೀಡಲಾಗಿದೆ. ಯಾವುದೇ ನೈಜ ಹೂಡಿಕೆಯು ಲಾಭದ ಖಾತರಿ ನೀಡಲು ಸಾಧ್ಯವಿಲ್ಲ.",
  },
  "rule.invest_pay_to_withdraw": {   // A4
    en: "Asks you to pay a fee or tax before you can withdraw your money.",
    hi: "अपना धन निकालने से पहले शुल्क या कर जमा करने को कहा गया है।",
    kn: "ನಿಮ್ಮ ಹಣವನ್ನು ಹಿಂಪಡೆಯುವ ಮೊದಲು ಶುಲ್ಕ ಅಥವಾ ತೆರಿಗೆ ಪಾವತಿಸುವಂತೆ ಕೇಳಲಾಗಿದೆ.",
  },
  "rule.invest_vip_group": {   // A5
    en: "Invites you to a paid or VIP tips group.",
    hi: "सशुल्क या VIP टिप्स समूह से जुड़ने का आमंत्रण दिया गया है।",
    kn: "ಪಾವತಿಸಿದ ಅಥವಾ VIP ಟಿಪ್ಸ್ ಗುಂಪಿಗೆ ಸೇರಲು ಆಹ್ವಾನಿಸಲಾಗಿದೆ.",
  },
  "rule.invest_credentials": {   // A6
    en: "Asks for your trading login or offers to run your account.",
    hi: "आपके ट्रेडिंग खाते का लॉगिन साझा करने, या आपका खाता संभालने की पेशकश की गई है।",
    kn: "ನಿಮ್ಮ ಟ್ರೇಡಿಂಗ್ ಲಾಗಿನ್ ಹಂಚಿಕೊಳ್ಳಲು ಅಥವಾ ನಿಮ್ಮ ಖಾತೆಯನ್ನು ನಿರ್ವಹಿಸಲು ಪ್ರಸ್ತಾಪಿಸಲಾಗಿದೆ.",
  },
  "rule.invest_task_pay": {   // A7
    en: "Promises daily pay for simple online tasks.",
    hi: "सरल ऑनलाइन कार्यों के बदले प्रतिदिन कमाई का वादा किया गया है।",
    kn: "ಸರಳ ಆನ್‌ಲೈನ್ ಕೆಲಸಗಳಿಗೆ ದಿನನಿತ್ಯದ ಗಳಿಕೆಯ ಭರವಸೆ ನೀಡಲಾಗಿದೆ.",
  },
  "rule.invest_task_prepaid": {   // A8
    en: "Asks for a deposit to unlock tasks or higher levels.",
    hi: "कार्य या उच्च स्तर खोलने के लिए अग्रिम राशि जमा करने को कहा गया है।",
    kn: "ಕಾರ್ಯಗಳು ಅಥವಾ ಮೇಲಿನ ಹಂತಗಳನ್ನು ತೆರೆಯಲು ಮುಂಗಡ ಹಣ ಜಮಾ ಮಾಡುವಂತೆ ಕೇಳಲಾಗಿದೆ.",
  },
  "rule.invest_app": {   // A9
    en: "Asks you to install a trading app from a link.",
    hi: "लिंक के माध्यम से ट्रेडिंग ऐप इंस्टॉल करने को कहा गया है।",
    kn: "ಲಿಂಕ್ ಮೂಲಕ ಟ್ರೇಡಿಂಗ್ ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡುವಂತೆ ಕೇಳಲಾಗಿದೆ.",
  },
  "rule.invest_ipo_allotment": {   // A10
    en: "Offers IPO pre-allotment or an institutional account through a group or app.",
    hi: "किसी समूह या ऐप के माध्यम से IPO का प्री-अलॉटमेंट या संस्थागत खाते की पेशकश की गई है।",
    kn: "ಗುಂಪು ಅಥವಾ ಆ್ಯಪ್ ಮೂಲಕ IPO ಪೂರ್ವ-ಹಂಚಿಕೆ ಅಥವಾ ಸಾಂಸ್ಥಿಕ ಖಾತೆಯ ಪ್ರಸ್ತಾಪ ನೀಡಲಾಗಿದೆ.",
  },
  "rule.invest_celebrity": {   // A11
    en: "Uses a minister's or celebrity's name to promote an investment.",
    hi: "निवेश योजना के प्रचार में किसी मंत्री या प्रसिद्ध व्यक्ति के नाम का उपयोग किया गया है।",
    kn: "ಹೂಡಿಕೆ ಯೋಜನೆಯ ಪ್ರಚಾರಕ್ಕೆ ಸಚಿವರು ಅಥವಾ ಖ್ಯಾತ ವ್ಯಕ್ತಿಯ ಹೆಸರನ್ನು ಬಳಸಲಾಗಿದೆ.",
  },
  "rule.invest_crypto": {   // A12
    en: "Asks you to deposit or pay in crypto to earn or trade.",
    hi: "कमाई या ट्रेडिंग के लिए क्रिप्टो में राशि जमा करने या भुगतान करने को कहा गया है।",
    kn: "ಗಳಿಕೆ ಅಥವಾ ಟ್ರೇಡಿಂಗ್‌ಗಾಗಿ ಕ್ರಿಪ್ಟೋದಲ್ಲಿ ಹಣ ಜಮಾ ಮಾಡುವಂತೆ ಅಥವಾ ಪಾವತಿಸುವಂತೆ ಕೇಳಲಾಗಿದೆ.",
  },
};

/** Short radar labels, English only (the radar is not translated). Equal to the API's Evidence.tag; here for the test that keeps the two in step. */
export const INVEST_TAGS: Record<string, string> = {
  "rule.invest_upi": "Non-@valid UPI", "rule.invest_sebi_claim": "SEBI claim", "rule.invest_guaranteed": "Guaranteed returns",
  "rule.invest_pay_to_withdraw": "Pay to withdraw", "rule.invest_vip_group": "VIP tips group", "rule.invest_credentials": "Login sharing",
  "rule.invest_task_pay": "Task pay promise", "rule.invest_task_prepaid": "Prepaid task", "rule.invest_app": "Install app",
  "rule.invest_ipo_allotment": "IPO allotment", "rule.invest_celebrity": "Celebrity scheme", "rule.invest_crypto": "Crypto deposit",
};

/** The investment card in What to do now: the one SEBI advice line the API adds to Report.advice when a rule fired (English, exactly as the API
 *  sends it, which is how the card is recognised), its heading and its Hindi / Kannada versions. */
export const INVEST_ADVICE: Record<HelpLang, string> = {
  en: "SEBI-registered brokers and advisers collect UPI payments only through IDs with the @valid handle (for example name.brk@validhdfc), and never promise guaranteed returns. Check any adviser at sebi.gov.in before paying.",
  hi: "SEBI-पंजीकृत ब्रोकर और सलाहकार UPI भुगतान केवल @valid हैंडल वाली आईडी (उदाहरण के लिए name.brk@validhdfc) के माध्यम से ही स्वीकार करते हैं और गारंटीशुदा रिटर्न का वादा कभी नहीं करते। भुगतान से पहले sebi.gov.in पर संबंधित सलाहकार की जाँच करें।",
  kn: "SEBI-ನೋಂದಾಯಿತ ಬ್ರೋಕರ್‌ಗಳು ಮತ್ತು ಸಲಹೆಗಾರರು UPI ಪಾವತಿಗಳನ್ನು @valid ಹ್ಯಾಂಡಲ್ ಹೊಂದಿರುವ ಐಡಿಗಳ (ಉದಾಹರಣೆಗೆ name.brk@validhdfc) ಮೂಲಕ ಮಾತ್ರ ಸ್ವೀಕರಿಸುತ್ತಾರೆ ಮತ್ತು ಖಚಿತ ಲಾಭದ ಭರವಸೆಯನ್ನು ಎಂದಿಗೂ ನೀಡುವುದಿಲ್ಲ. ಪಾವತಿಸುವ ಮೊದಲು sebi.gov.in ನಲ್ಲಿ ಸಲಹೆಗಾರರನ್ನು ಪರಿಶೀಲಿಸಿ.",
};
export const INVEST_HEADING: Record<HelpLang, string> = { en: "Before you invest", hi: "निवेश से पहले", kn: "ಹೂಡಿಕೆ ಮಾಡುವ ಮುನ್ನ" };

/** Whether this advice line is the investment card's. */
export const isInvestAdvice = (line: string): boolean => line === INVEST_ADVICE.en;

/** The reason to show for an evidence in `lang`: the translation for an investment rule, else the text the API sent (English, and every other reason). */
export function reasonText(sent: string, evidence: Evidence | null, lang: HelpLang): string {
  const t = evidence && lang !== "en" ? INVEST_REASONS[evidence.id]?.[lang] : undefined;
  return t ?? sent;
}
