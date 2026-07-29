/**
 * Signature database of known prompt-injection patterns. Each signature carries
 * a weight in [0, 1); the detector combines them with a noisy-OR.
 *
 * GENERATED FILE — DO NOT EDIT.
 * Source of truth: python/src/bulwark/patterns.py
 * Regenerate:      python3 tools/gen_patterns.py
 *
 * Three hand-maintained copies of one signature database is how they drift, so
 * there is one copy and two generated from it.
 */


import type { Severity } from "./types.js";

export interface Signature {
  id: string;
  category: string;
  severity: Severity;
  weight: number;
  regex: RegExp;
  description: string;
}

function sig(
  id: string,
  category: string,
  severity: Severity,
  weight: number,
  pattern: string,
  description: string,
): Signature {
  // `u` gives \p{...} its meaning; `i` and `m` mirror Python's
  // re.IGNORECASE | re.MULTILINE.
  return { id, category, severity, weight, regex: new RegExp(pattern, "imu"), description };
}

export const SIGNATURES: Signature[] = [
  sig(
    "io.ignore_previous", "instruction_override", "critical", 0.86,
    "\\bignore\\s+(?:all\\s+|any\\s+|the\\s+)*(?:previous|prior|preceding|above|earlier|foregoing|former)\\b.{0,40}?\\b(?:instruction|prompt|message|context|rule|direction|command|guideline)s?\\b",
    "Asks the model to ignore previous instructions",
  ),
  sig(
    "io.disregard", "instruction_override", "critical", 0.86,
    "\\b(?:disregard|forget|discard|overlook|set\\s+aside)\\s+(?:all\\s+|any\\s+|the\\s+)*(?:previous|prior|above|earlier|your)\\b.{0,40}?\\b(?:instruction|prompt|rule|direction|context)s?\\b",
    "Asks the model to disregard prior instructions",
  ),
  sig(
    "io.ignore_above", "instruction_override", "high", 0.74,
    "\\b(?:disregard|ignore|forget|skip)\\s+(?:all\\s+|any\\s+|everything\\s+)?(?:the\\s+)?(?:above|preceding|foregoing|earlier\\s+text)\\b",
    "Asks the model to ignore/disregard the text above",
  ),
  sig(
    "io.forget_everything", "instruction_override", "high", 0.78,
    "\\bforget\\s+(?:everything|all|what)\\b.{0,40}?(?:said|instructed|above|told|before)",
    "Asks the model to forget everything it was told",
  ),
  sig(
    "io.new_instructions", "instruction_override", "high", 0.74,
    "\\b(?:new|updated|revised|real|actual|true|correct|important)\\s+(?:instruction|task|directive|order|system\\s+prompt)s?\\b\\s*[:\\-—]",
    "Introduces replacement 'new instructions'",
  ),
  sig(
    "io.do_not_summarize", "instruction_override", "high", 0.72,
    "\\bdo\\s+not\\s+(?:summari[sz]e|follow\\s+the\\s+(?:original|system|above))",
    "Tells the model not to perform its real task",
  ),
  sig(
    "io.instead_of", "instruction_override", "high", 0.72,
    "\\binstead\\s+of\\s+(?:summari[sz]ing|following|doing)\\b",
    "Redirects the model away from its task",
  ),
  sig(
    "io.override", "instruction_override", "high", 0.7,
    "\\boverride\\b.{0,30}?\\b(?:instruction|prompt|system|rule|setting|safety)s?\\b",
    "Asks to override instructions or safety settings",
  ),
  sig(
    "io.from_now_on", "instruction_override", "medium", 0.45,
    "\\bfrom\\s+now\\s+on\\b.{0,40}?\\byou\\s+(?:will|must|should|shall)\\b",
    "Attempts to install a new standing directive",
  ),
  sig(
    "io.cancel_task", "instruction_override", "medium", 0.5,
    "\\b(?:cancel|abort|skip|stop)\\s+(?:the\\s+|your\\s+)?(?:summary|summari[sz]ation|summari[sz]ing|task|above\\s+task)\\b",
    "Tells the model to cancel/abort its real task",
  ),
  sig(
    "io.reset_context", "instruction_override", "medium", 0.5,
    "\\b(?:reset|clear|wipe|erase|flush)\\b.{0,20}?\\b(?:context|memory|conversation|chat\\s+history|history|everything\\s+(?:above|so\\s+far))\\b",
    "Asks the model to reset/clear its context or memory",
  ),
  sig(
    "role.chatml", "role_injection", "critical", 0.82,
    "<\\|\\s*(?:im_start|im_end|im_sep|system|assistant|user|endoftext)\\s*\\|>",
    "ChatML / special role tokens",
  ),
  sig(
    "role.inst", "role_injection", "high", 0.74,
    "\\[/?\\s*(?:INST|SYS)\\s*\\]",
    "Llama-style [INST]/[SYS] role markers",
  ),
  sig(
    "role.line_marker", "role_injection", "high", 0.66,
    "^[ \\t]*(?:system|assistant|developer)[ \\t]*(?:message)?[ \\t]*:[ \\t]*\\S",
    "Line begins with a system/assistant role label",
  ),
  sig(
    "role.markdown_header", "role_injection", "medium", 0.52,
    "^#{1,6}\\s*(?:System|Instruction|Assistant|Developer)\\b",
    "Markdown header impersonating a system section",
  ),
  sig(
    "role.xml_tag", "role_injection", "medium", 0.5,
    "<\\s*/?\\s*(?:system|assistant|developer)(?:_prompt)?\\s*>",
    "XML-style system/assistant tags",
  ),
  sig(
    "role.begin_system", "role_injection", "high", 0.7,
    "\\bbegin\\s+(?:system|new)\\s+(?:prompt|instructions?)\\b",
    "Declares the beginning of a system prompt",
  ),
  sig(
    "leak.reveal_prompt", "prompt_leak", "high", 0.8,
    "\\b(?:reveal|repeat|print|show|output|echo|display|reproduce|spell\\s+out|tell\\s+me)\\b.{0,30}?\\b(?:system\\s+prompt|your\\s+(?:instructions|prompt|system|rules|guidelines)|initial\\s+(?:prompt|instructions)|the\\s+(?:prompt|text)\\s+above|everything\\s+above)\\b",
    "Tries to exfiltrate the system prompt",
  ),
  sig(
    "leak.what_are_instructions", "prompt_leak", "high", 0.74,
    "\\bwhat\\s+(?:are|were)\\s+your\\s+(?:original\\s+|initial\\s+)?(?:system\\s+)?(?:instructions|prompt|rules|guidelines|directives)\\b",
    "Asks the model to disclose its instructions",
  ),
  sig(
    "leak.begin_reply_with", "prompt_leak", "high", 0.7,
    "\\b(?:begin|start|prefix|preface)\\s+(?:your\\s+)?(?:reply|answer|response|the\\s+summary|output)\\s+(?:with|by)\\b",
    "Tries to control the start of the output",
  ),
  sig(
    "leak.verbatim", "prompt_leak", "medium", 0.55,
    "\\b(?:repeat|output|print)\\b.{0,20}?\\b(?:verbatim|word\\s+for\\s+word|exactly)\\b",
    "Asks for verbatim reproduction",
  ),
  sig(
    "exfil.markdown_image", "exfiltration", "high", 0.8,
    "!\\[[^\\]]*\\]\\(\\s*https?://(?!(?:img\\.shields\\.io|badge\\.fury\\.io|codecov\\.io|coveralls\\.io|circleci\\.com|travis-ci\\.(?:org|com)|app\\.travis-ci\\.com|camo\\.githubusercontent\\.com|api\\.netlify\\.com|snyk\\.io|deps\\.rs|badgen\\.net|img\\.badgesize\\.io|github\\.com/[^)\\s]*/(?:badge|workflows|actions))\\b)[^)\\s]*[?&#][\\p{L}\\p{N}_.\\-%]+=[^)\\s&]{4,}",
    "Markdown image whose URL carries data — a classic exfiltration channel",
  ),
  sig(
    "exfil.send_to_url", "exfiltration", "critical", 0.84,
    "\\b(?:send|post|exfiltrate|upload|transmit|leak|forward|report|deliver)\\b.{0,50}?\\bhttps?://",
    "Asks the model to send data to a URL",
  ),
  sig(
    "exfil.fetch", "exfiltration", "high", 0.72,
    "\\b(?:you\\s+(?:should|must|will|need\\s+to)\\s+)?(?:fetch|retrieve|open|visit|browse\\s+to|navigate\\s+to|load|request)\\s+(?:the\\s+(?:url|link|page)\\s+)?`?https?://",
    "Asks the model to fetch/visit a URL",
  ),
  sig(
    "exfil.append_to_url", "exfiltration", "high", 0.74,
    "\\bappend\\b.{0,30}?\\bto\\s+the\\s+(?:url|link|image|address|query)\\b",
    "Asks to append data to a URL (exfiltration)",
  ),
  sig(
    "exfil.include_link", "exfiltration", "medium", 0.5,
    "\\b(?:include|embed|add|insert)\\b.{0,30}?\\b(?:tracking\\s+pixel|this\\s+(?:link|image|url))\\b",
    "Asks to embed a link/pixel in the output",
  ),
  sig(
    "exfil.markdown_link_data", "exfiltration", "high", 0.7,
    "\\[[^\\]]*\\]\\(\\s*https?://[^)]*[?&][\\p{L}\\p{N}_.\\-%]+=[A-Za-z0-9+/=_\\-]{16,}",
    "Markdown link carrying a long, data-bearing query string (exfiltration channel)",
  ),
  sig(
    "jb.dan", "jailbreak", "high", 0.78,
    "\\b(?:you\\s+are\\s+(?:now\\s+)?DAN\\b|\\bDAN\\s+(?:mode|prompt)\\b|do\\s+anything\\s+now\\b|(?:enable|enter|activate|switch\\s+to|you\\s+are\\s+in)\\s+developer\\s+mode\\b|(?:this\\s+is\\s+a\\s+|perform\\s+a\\s+|run\\s+the\\s+)?jailbreak\\s+(?:prompt|mode|now)\\b|\\bSTAN\\s+mode\\b|\\bAIM\\s+mode\\b)",
    "Known jailbreak persona / phrase",
  ),
  sig(
    "jb.you_are_now", "jailbreak", "high", 0.7,
    "\\byou\\s+are\\s+(?:now\\s+)?(?:DAN\\b|an?\\s+(?:unrestricted|unfiltered|uncensored|amoral|evil)\\b)",
    "Reassigns the model to an unrestricted persona",
  ),
  sig(
    "jb.no_restrictions", "jailbreak", "high", 0.68,
    "\\b(?:no\\s+(?:longer\\s+)?(?:bound|restricted|limited)\\s+by|without\\s+any\\s+(?:restrictions|filters|rules|guidelines|limitations))\\b",
    "Claims the model has no restrictions",
  ),
  sig(
    "jb.pretend", "jailbreak", "medium", 0.4,
    "\\b(?:pretend|imagine|roleplay|role-play)\\s+(?:that\\s+)?(?:to\\s+be|you\\s+are|you're)\\b",
    "Roleplay framing used to bypass rules",
  ),
  sig(
    "jb.act_as", "jailbreak", "low", 0.28,
    "\\bact\\s+as\\s+(?:if\\s+you\\s+(?:are|were)\\s+|a\\s+|an\\s+|the\\s+)",
    "'Act as' framing (often benign — low weight)",
  ),
  sig(
    "jb.unlock_mode", "jailbreak", "high", 0.62,
    "\\b(?:unlock|enable|activate|enter|switch\\s+to)\\b.{0,20}?\\b(?:developer|god|admin|root|debug|unrestricted|dan)\\s+mode\\b",
    "Tries to enable an unrestricted/developer mode",
  ),
  sig(
    "jb.hypothetical", "jailbreak", "medium", 0.5,
    "\\b(?:hypothetical(?:ly)?|fictional|in\\s+a\\s+(?:fictional|hypothetical|imaginary)\\s+(?:world|scenario|story))\\b.{0,40}?\\b(?:no\\s+(?:rules|restrictions|guidelines|limits)|anything\\s+is\\s+(?:allowed|permitted|possible)|you\\s+can\\s+do\\s+anything|without\\s+(?:any\\s+)?(?:rules|restrictions))\\b",
    "Hypothetical/fictional framing used to lift restrictions",
  ),
  sig(
    "tool.call_function", "tool_injection", "low", 0.2,
    "\\b(?:call|invoke|execute|run|trigger)\\b.{0,25}?\\b(?:function|tool|command|api|endpoint|webhook)\\b",
    "Mentions calling a tool or endpoint (weak — every devops page reads like this)",
  ),
  sig(
    "tool.json_call", "tool_injection", "medium", 0.55,
    "\"(?:function_call|tool_call|name|arguments)\"\\s*:",
    "Inline tool-call JSON",
  ),
  sig(
    "tool.destructive", "tool_injection", "low", 0.22,
    "\\b(?:delete|drop|wipe|erase|rm\\s+-rf|truncate|format)\\b.{0,25}?\\b(?:file|files|database|table|record|directory|everything|all\\s+data)\\b",
    "Mentions a destructive operation (weak — runbooks and SQL tutorials say this)",
  ),
  sig(
    "tool.shell_exec", "tool_injection", "low", 0.22,
    "\\b(?:execute|run|eval(?:uate)?)\\b.{0,20}?\\b(?:shell|bash|sh|zsh|code|script|python|os\\.system|subprocess|powershell|cmd|terminal)\\b",
    "Mentions running a script (weak — tutorials are full of this)",
  ),
  sig(
    "bnd.end_of_document", "boundary_breakout", "medium", 0.58,
    "\\bEND\\s+OF\\s+(?:DOCUMENT|CONTENT|DATA|UNTRUSTED|INPUT|PAGE|ARTICLE|TEXT)\\b",
    "Fake 'end of document' boundary",
  ),
  sig(
    "bnd.close_wrapper", "boundary_breakout", "medium", 0.56,
    "</\\s*(?:untrusted|document|content|data|user_input|context)\\s*>",
    "Tries to close the containing wrapper",
  ),
  sig(
    "bnd.dashes_end", "boundary_breakout", "low", 0.3,
    "^-{3,}\\s*(?:END|STOP|SYSTEM|ASSISTANT)\\b",
    "Dashed separator followed by a control word",
  ),
  sig(
    "enc.base64_blob", "encoding", "low", 0.22,
    "\\b[A-Za-z0-9+/]{60,}={0,2}\\b",
    "Long Base64-looking blob (possible hidden payload)",
  ),
  sig(
    "enc.decode_request", "encoding", "medium", 0.5,
    "\\b(?:decode|base64-?decode|rot13|reverse|unscramble)\\b.{0,30}?\\b(?:and|then)\\b.{0,20}?\\b(?:follow|execute|run|do|obey)\\b",
    "Asks the model to decode then execute",
  ),
  sig(
    "adv.precedence", "instruction_override", "high", 0.78,
    "\\bthis\\s+(?:message|instruction|prompt|text|note)\\b.{0,30}?\\b(?:overrides|supersedes|takes\\s+precedence|replaces|cancels)\\b",
    "Claims to override/supersede the real instructions",
  ),
  sig(
    "adv.disable_safety", "jailbreak", "high", 0.74,
    "\\b(?:disable|turn\\s+off|bypass|ignore|remove|switch\\s+off|lift|suspend)\\b[^.\\n]{0,25}?\\b(?:your|all|any|the)?\\s*(?:safety\\s+(?:rules?|guidelines?|filters?|protocols?)|guardrails?|content\\s+policy|content\\s+moderation|ethical\\s+(?:guidelines?|constraints?)|alignment|restrictions?\\s+(?:on\\s+you|you\\s+(?:have|were\\s+given)))\\b",
    "Asks to disable safety / guardrails",
  ),
  sig(
    "adv.respond_only_with", "instruction_override", "high", 0.7,
    "\\b(?:respond|reply|answer|output|say|write|print)\\s+(?:only\\s+)?(?:with|the\\s+following|exactly)\\b.{0,30}?[\"'`:]",
    "Tries to force exact/verbatim output",
  ),
  sig(
    "adv.identity_reassign", "jailbreak", "medium", 0.52,
    "\\byou\\s+are\\s+(?:now\\s+)?(?:chatgpt|claude|gemini|gpt-?\\d|bard|an?\\s+ai\\s+language\\s+model|a\\s+helpful\\s+assistant\\s+that\\s+(?:has\\s+no|ignores))\\b",
    "Reassigns the assistant's identity",
  ),
  sig(
    "adv.system_override_tag", "role_injection", "high", 0.72,
    "<\\s*/?\\s*(?:system_override|admin|root|sudo|override|jailbreak|important_instructions?)\\s*>",
    "Fake authority/override XML tag",
  ),
  sig(
    "adv.human_turn", "role_injection", "medium", 0.55,
    "^[ \\t]*(?:Human|User|AI)[ \\t]*:[ \\t]*\\S",
    "Line forges a conversation turn (Human:/User:/AI:)",
  ),
  sig(
    "adv.repeat_above", "prompt_leak", "high", 0.72,
    "\\b(?:repeat|print|output|write)\\b.{0,20}?\\b(?:everything|the\\s+words?|all\\s+text|the\\s+text)\\b.{0,15}?\\babove\\b",
    "Asks to repeat everything above (prompt extraction)",
  ),
  sig(
    "adv.confirm_by", "instruction_override", "medium", 0.5,
    "\\bto\\s+(?:confirm|prove|show)\\b.{0,30}?\\b(?:reply|respond|say|answer|output|write)\\b\\s+[\"'`]?[\\p{L}\\p{N}_]",
    "'To confirm, reply with X' compliance bait",
  ),
  sig(
    "adv.important_notice", "instruction_override", "low", 0.32,
    "\\b(?:important|urgent|critical|attention)\\b[:!]?\\s+(?:system\\s+)?(?:message|notice|update|instruction|announcement|alert)\\b",
    "Authority-framed 'important notice' lead-in",
  ),
  sig(
    "adv.email_exfil", "exfiltration", "high", 0.74,
    "\\b(?:e-?mail|mail|dm|message|text)\\b.{0,25}?\\b(?:this|the\\s+(?:above|summary|data|conversation|results?)|it)\\b.{0,15}?\\bto\\b\\s+\\S+@",
    "Asks to email data to an address",
  ),
  sig(
    "adv.grandma", "jailbreak", "medium", 0.4,
    "\\bmy\\s+(?:deceased\\s+|late\\s+|dead\\s+)?(?:grandm(?:a|other)|grandpa|grandfather)\\b.{0,40}?\\b(?:used\\s+to|would)\\b",
    "'Grandma' role-play jailbreak framing",
  ),
  sig(
    "adv.continue_as", "instruction_override", "medium", 0.55,
    "\\b(?:continue|proceed|respond)\\b.{0,20}?\\bas\\s+(?:if|though)\\b.{0,30}?\\b(?:no\\s+(?:restrictions|rules|guidelines)|unrestricted|nothing\\s+is\\s+forbidden)\\b",
    "Asks to continue as if unrestricted",
  ),
  sig(
    "ml.ignore_fr", "instruction_override", "high", 0.8,
    "\\bignor[\\p{L}\\p{N}_]*\\b.{0,40}?\\b(?:instructions?|consignes?|directives?)\\b.{0,25}?\\b(?:pr[ée]c[ée]dentes?|ant[ée]rieures?|ci-dessus)\\b",
    "Ignore-previous-instructions (French)",
  ),
  sig(
    "ml.ignore_es", "instruction_override", "high", 0.8,
    "\\bignor[\\p{L}\\p{N}_]*\\b.{0,40}?\\binstrucciones\\b.{0,25}?\\b(?:anteriores|previas)\\b",
    "Ignore-previous-instructions (Spanish)",
  ),
  sig(
    "ml.ignore_de", "instruction_override", "high", 0.8,
    "\\bignorier[\\p{L}\\p{N}_]*\\b.{0,40}?\\b(?:vorherigen|obigen|bisherigen|vorigen)\\b.{0,25}?\\banweisungen\\b",
    "Ignore-previous-instructions (German)",
  ),
  sig(
    "ml.ignore_pt", "instruction_override", "high", 0.8,
    "\\bignor[\\p{L}\\p{N}_]*\\b.{0,40}?\\binstru[çc][õo]es\\b.{0,25}?\\banteriores\\b",
    "Ignore-previous-instructions (Portuguese)",
  ),
  sig(
    "ml.ignore_it", "instruction_override", "high", 0.8,
    "\\bignor[\\p{L}\\p{N}_]*\\b.{0,40}?\\bistruzioni\\b.{0,25}?\\bprecedenti\\b",
    "Ignore-previous-instructions (Italian)",
  ),
  sig(
    "ml.ignore_ru", "instruction_override", "high", 0.8,
    "игнорир[а-яё]*[\\s\\S]{0,30}?(?:инструкции|указания|команды|правила)",
    "Ignore-instructions (Russian)",
  ),
  sig(
    "ml.ignore_zh", "instruction_override", "high", 0.82,
    "(?:忽略|无视|忽視|無視)[^。\\n]{0,10}(?:指令|指示|提示|命令|规则|規則)",
    "Ignore-instructions (Chinese)",
  ),
  sig(
    "ml.ignore_ja", "instruction_override", "high", 0.8,
    "(?:指示|命令|指令)を[^。\\n]{0,6}無視",
    "Ignore-instructions (Japanese)",
  ),
  sig(
    "ml.reveal_zh", "prompt_leak", "high", 0.78,
    "(?:显示|输出|告诉我|泄露|重复|打印)[^。\\n]{0,8}(?:系统提示|系统指令|你的指令|提示词|初始指令)",
    "Reveal-system-prompt (Chinese)",
  ),
  sig(
    "ml.ignore_ko", "instruction_override", "high", 0.8,
    "(?:이전|모든|위의|앞의)[^。\\n]{0,12}(?:지시|명령|지침|규칙)[^。\\n]{0,8}무시",
    "Ignore-instructions (Korean)",
  ),
  sig(
    "ml.ignore_ar", "instruction_override", "high", 0.8,
    "تجاهل[\\s\\S]{0,30}?(?:التعليمات|الإرشادات|الأوامر|التعليمة)[\\s\\S]{0,20}?(?:السابقة|أعلاه|السابقه)",
    "Ignore-previous-instructions (Arabic)",
  ),
  sig(
    "ml.ignore_hi", "instruction_override", "high", 0.8,
    "(?:पिछले|सभी|उपरोक्त|पिछली)[\\s\\S]{0,20}?(?:निर्देश|निर्देशों|आदेश)[\\s\\S]{0,20}?(?:अनदेखा|नज़रअंदाज़|अनदेखी|नजरअंदाज)",
    "Ignore-previous-instructions (Hindi)",
  ),
  sig(
    "ml.ignore_tr", "instruction_override", "high", 0.8,
    "önceki[\\s\\S]{0,30}?talimat[\\s\\S]{0,20}?(?:yok\\s*say|görmezden|dikkate\\s+alma|gözardı)",
    "Ignore-previous-instructions (Turkish)",
  ),
  sig(
    "ml.ignore_nl", "instruction_override", "high", 0.8,
    "negeer[\\s\\S]{0,30}?(?:voorgaande|vorige|bovenstaande|eerdere)[\\s\\S]{0,20}?(?:instructies|aanwijzingen|opdrachten)",
    "Ignore-previous-instructions (Dutch)",
  ),
  sig(
    "ml.ignore_pl", "instruction_override", "high", 0.8,
    "(?:zignoruj|ignoruj|pomiń)[\\s\\S]{0,30}?(?:poprzednie|powyższe|wcześniejsze)[\\s\\S]{0,20}?(?:instrukcje|polecenia|wytyczne)",
    "Ignore-previous-instructions (Polish)",
  ),
  sig(
    "ai.conditional_identity", "instruction_override", "critical", 0.86,
    "\\bif\\s+you(?:'re|\\s+are)\\s+(?:an?\\s+)?(?:ai\\b|a\\.i\\.|llm\\b|language\\s+model|assistant\\b|agent\\b|bot\\b|chatbot\\b|automated|machine|model\\s+reading|reading\\s+this\\s+as\\s+an\\s+ai)",
    "Addresses the reader conditionally as an AI — content written for a model, not a person",
  ),
  sig(
    "ai.note_for_model", "instruction_override", "critical", 0.84,
    "\\b(?:note|notice|message|instruction|reminder|attention|important|memo|hint)s?\\s+(?:for|to)\\s+(?:the\\s+|any\\s+|all\\s+)?(?:ai\\b|a\\.i\\.|llm\\b|language\\s+model|assistant|agent|bot|copilot|model|chatgpt|claude|gemini|summari[sz]er|reviewer\\s+bot|crawler)",
    "A note explicitly addressed to an AI assistant",
  ),
  sig(
    "ai.direct_address", "instruction_override", "high", 0.78,
    "\\b(?:hey|hi|hello|dear|ok(?:ay)?|attention|listen)[,\\s]+(?:ai\\b|assistant\\b|agent\\b|bot\\b|copilot\\b|claude\\b|chatgpt\\b|gemini\\b|llm\\b|language\\s+model\\b)",
    "Greets the model directly inside the content",
  ),
  sig(
    "ai.role_prefix", "role_injection", "high", 0.72,
    "^[ \\t]*(?:<[@#]?[\\p{L}\\p{N}_]+>[ \\t]*)?(?:ai|llm)?[ \\t]*(?:assistant|agent|bot|copilot|summari[sz]er|reviewer[ \\t]bot|coding[ \\t]agent)[ \\t]*[,:][ \\t]*\\S",
    "A line addressed to the assistant by role",
  ),
  sig(
    "ai.for_agents_processing", "instruction_override", "high", 0.8,
    "\\bfor\\s+(?:any\\s+|all\\s+|the\\s+)?(?:ai\\s+)?(?:assistants?|agents?|bots?|models?|llms?|automated\\s+(?:readers?|systems?|tools?))\\s+(?:that\\s+are\\s+)?(?:reading|processing|performing|handling|viewing|parsing|summari[sz]ing|reviewing)",
    "Gives directions to any AI processing the document",
  ),
  sig(
    "ai.model_imperative", "instruction_override", "high", 0.74,
    "\\b(?:assistant|ai\\s+agent|the\\s+agent|the\\s+model|copilot)\\s*[,:]?\\s+(?:you\\s+)?(?:must|should|shall|need\\s+to|are\\s+to|is\\s+to|please)\\b",
    "Issues an obligation to the assistant by name",
  ),
  sig(
    "ai.when_you_task", "instruction_override", "medium", 0.56,
    "\\bwhen\\s+you\\s+(?:summari[sz]e|process|read|handle|review|redact|answer|respond\\s+to|report\\s+on)\\s+(?:this|these|the\\s+(?:document|page|article|ticket|file))",
    "Conditions an instruction on the model performing its task",
  ),
  sig(
    "ai.before_you_act", "instruction_override", "medium", 0.58,
    "\\bbefore\\s+(?:you\\s+)?(?:continue|proceed|respond|reply|answer|summari[sz]e|summari[sz]ing|running|joining|approving|doing\\s+anything)\\b[^.\\n]{0,60}?\\b(?:you\\s+must|first|please|make\\s+sure|be\\s+sure|remember\\s+to)\\b",
    "Inserts a prerequisite step before the model's real task",
  ),
  sig(
    "ag.already_approved", "tool_injection", "high", 0.72,
    "\\b(?:the\\s+)?(?:user|owner|admin(?:istrator)?|maintainer|operator)\\s+(?:has\\s+)?(?:already\\s+)?(?:approved|confirmed|authori[sz]ed|consented|signed\\s+off|pre-?approved)\\b",
    "Manufactures user consent the model never received",
  ),
  sig(
    "ag.no_confirmation_needed", "tool_injection", "high", 0.78,
    "\\b(?:no|without)\\s+(?:further\\s+|additional\\s+|explicit\\s+|user\\s+)?(?:confirmation|approval|permission|verification|authori[sz]ation)\\s+(?:is\\s+)?(?:needed|required|necessary)\\b",
    "Claims no confirmation is required for an action",
  ),
  sig(
    "ag.skip_confirmation", "tool_injection", "high", 0.78,
    "\\b(?:skip|bypass|suppress|dismiss|auto-?(?:accept|approve|confirm)|ignore)\\b[^.\\n]{0,30}?\\b(?:confirmation|approval\\s+(?:step|dialog|prompt)|safety\\s+check|security\\s+(?:check|warning)|verification\\s+step)\\b",
    "Asks the agent to skip a confirmation or safety step",
  ),
  sig(
    "ag.you_are_authorized", "tool_injection", "high", 0.74,
    "\\byou\\s+(?:are|have\\s+been|'re)\\s+(?:pre-?)?(?:authori[sz]ed|permitted|allowed|cleared|approved|entitled)\\s+to\\b",
    "Grants the model an authority the content cannot grant",
  ),
  sig(
    "ag.warning_was_false", "tool_injection", "high", 0.76,
    "\\b(?:previous|prior|earlier|the|any)\\s+(?:security\\s+)?(?:warning|alert|flag|notice|error|block)[\\p{L}\\p{N}_]*\\b[^.\\n]{0,40}?\\b(?:false\\s+positive|can\\s+be\\s+(?:safely\\s+)?ignored|is\\s+incorrect|was\\s+a\\s+mistake|does\\s+not\\s+apply|no\\s+longer\\s+applies)\\b",
    "Tries to talk the agent out of a security decision it already made",
  ),
  sig(
    "ag.change_destination", "exfiltration", "high", 0.7,
    "\\b(?:change|update|replace|switch|correct|use|set)\\b[^.\\n]{0,30}?\\b(?:recipient|destination|delivery\\s+address|forwarding\\s+address|endpoint|callback|webhook|payee|payment\\s+(?:details|routing)|routing|wallet|bank\\s+account|iban)\\b[^.\\n]{0,20}?\\bto\\b",
    "Redirects where an action sends data or value",
  ),
  sig(
    "ag.fake_tool_schema", "tool_injection", "high", 0.68,
    "\\b(?:this\\s+(?:project|system|workspace|repo)\\s+(?:uses|has|provides)|there\\s+is)\\s+(?:a\\s+)?(?:custom\\s+|internal\\s+|hidden\\s+|undocumented\\s+)?(?:tool|function|command|api|endpoint)\\s+(?:named|called)\\b",
    "Announces a tool the model was never given — fake capability injection",
  ),
  sig(
    "sp.in_your_output", "summary_poisoning", "high", 0.7,
    "\\bin\\s+(?:your|the)\\s+(?:summary|response|answer|output|report|review|assessment|recommendation)\\b[^.\\n]{0,50}?\\b(?:include|mention|say|state|add|note|omit|exclude|leave\\s+out|do\\s+not|don't|make\\s+sure)\\b",
    "Dictates what the model's own output must contain or omit",
  ),
  sig(
    "sp.rate_favourably", "summary_poisoning", "high", 0.76,
    "\\b(?:give|provide|write|produce|return)\\s+(?:only\\s+)?(?:a\\s+)?(?:positive|favou?rable|glowing|strong|excellent|top)\\s+(?:review|rating|score|assessment|recommendation|evaluation)\\b",
    "Demands a favourable verdict — CV, peer-review and listing injection",
  ),
  sig(
    "sp.recommend_this", "summary_poisoning", "medium", 0.62,
    "\\b(?:recommend|endorse|rank|rate|present|describe)\\b[^.\\n]{0,30}?\\bthis\\s+(?:product|candidate|paper|submission|applicant|company|service|tool|vendor)\\b[^.\\n]{0,30}?\\b(?:as\\s+(?:the\\s+)?(?:best|top|leading|ideal|only)|highly|positively|favou?rably|first)\\b",
    "Asks the model to promote the document's subject",
  ),
  sig(
    "sp.do_not_mention", "summary_poisoning", "medium", 0.6,
    "\\bdo\\s+not\\s+(?:mention|include|report|reveal|disclose|summari[sz]e|discuss|refer\\s+to)\\b[^.\\n]{0,40}?\\b(?:this\\s+(?:notice|message|instruction|text|note)|the\\s+(?:above|following|preceding)|any\\s+of\\s+(?:this|the\\s+above))\\b",
    "Instructs the model to conceal part of the source from the user",
  ),
  sig(
    "role.gemma_turn", "role_injection", "high", 0.76,
    "<\\s*(?:start|end)_of_turn\\s*>|<\\|(?:start|end)_header_id\\|>|<\\|eot_id\\|>|<\\|assistant\\|>",
    "Chat-template turn markers from Gemma/Llama-3 style formats",
  ),
  sig(
    "role.tool_result_forgery", "role_injection", "high", 0.7,
    "<\\s*/?\\s*(?:tool_result|tool_response|tool_output|function_results?|function_response|observation|search_results?)\\s*>",
    "Forges a tool-result envelope so content reads as a trusted tool reply",
  ),
  sig(
    "bnd.dashes_authority", "boundary_breakout", "medium", 0.54,
    "^[ \\t]*[-=*_#]{2,}[ \\t]*(?:SYSTEM|ADMIN|OPERATOR|DEVELOPER|IMPORTANT|OVERRIDE|NEW\\s+INSTRUCTIONS?)\\b",
    "Separator followed by an authority label",
  ),
  sig(
    "leak.first_words", "prompt_leak", "high", 0.72,
    "\\b(?:what|repeat|print|output|show|tell\\s+me)\\b[^.\\n]{0,25}?\\b(?:first|initial|opening|very\\s+first)\\s+(?:\\d+\\s+)?(?:words?|lines?|paragraphs?|sentences?|characters?|tokens?)\\b",
    "Asks for the opening of the context — a prompt-extraction probe",
  ),
  sig(
    "leak.above_this_line", "prompt_leak", "high", 0.74,
    "\\beverything\\s+(?:written\\s+)?(?:above|before|preceding)\\s+(?:this|that)\\s+(?:line|point|message|marker|text)\\b",
    "Asks for everything above a marker — prompt extraction",
  ),
  sig(
    "auth.policy_supersedes", "instruction_override", "high", 0.76,
    "\\b(?:policy|guideline|rule|directive|protocol|handling)\\s+(?:update|change|revision|notice|bulletin)\\b[^.\\n]{0,60}?\\b(?:supersed|replac|overrid|effective\\s+immediately|takes\\s+effect)",
    "Fake policy update claiming to replace the operator's rules",
  ),
  sig(
    "auth.regulatory_obligation", "instruction_override", "high", 0.76,
    "\\b(?:automated\\s+systems?|assistants?|ai\\s+systems?|processing\\s+agents?|language\\s+models?)\\b[^.\\n]{0,50}?\\b(?:are\\s+)?(?:obliged|required|mandated|compelled|must\\s+comply)\\b[^.\\n]{0,40}?\\b(?:under|pursuant\\s+to|per|by)\\s+(?:art(?:icle)?\\.?\\s*\\d|regulation|directive|statute|law|gdpr|the\\s+act)",
    "Invents a legal obligation binding the model",
  ),
  sig(
    "auth.system_notice", "instruction_override", "high", 0.74,
    "\\b(?:scheduled\\s+maintenance|system\\s+(?:notice|maintenance|migration|upgrade)|service\\s+(?:notice|bulletin))\\b[^.\\n]{0,80}?\\b(?:instruction|prompt|directive|context|session)\\s+(?:channel|stream|set|state)?",
    "Fake infrastructure notice about the instruction channel",
  ),
  sig(
    "auth.effective_immediately", "instruction_override", "medium", 0.56,
    "\\beffective\\s+immediately\\b[^.\\n]{0,60}?\\b(?:assistants?|automated|ai\\b|models?|systems?)\\b",
    "'Effective immediately' framing aimed at automated readers",
  ),
  sig(
    "soc.no_time_to_check", "instruction_override", "high", 0.7,
    "\\b(?:no\\s+time|not\\s+enough\\s+time|too\\s+late|closes?\\s+in\\s+[\\p{L}\\p{N}_]+\\s+(?:minutes?|seconds?))\\b[^.\\n]{0,60}?\\b(?:skip|bypass|forgo|without|normal\\s+(?:review|process|checks?|procedure)|usual\\s+(?:review|checks?))\\b",
    "Urgency used to justify skipping a safeguard",
  ),
  sig(
    "soc.emotional_pressure", "jailbreak", "medium", 0.5,
    "\\b(?:my|our)\\s+(?:daughter|son|child|mother|father|wife|husband|job|career|visa|life|family)\\b[^.\\n]{0,80}?\\b(?:depends?\\s+on|tomorrow|urgent|please\\s+help|only\\s+chance|will\\s+be\\s+(?:lost|denied|fired))\\b",
    "Emotional pressure used to extract non-compliant behaviour",
  ),
  sig(
    "ai.instructed_to_lie", "instruction_override", "high", 0.8,
    "\\bif\\s+(?:you\\s+are\\s+|anyone\\s+|someone\\s+|the\\s+user\\s+)?(?:asked|questioned|queried|prompted)\\b[^.\\n]{0,50}?\\b(?:respond|reply|say|answer|state|tell\\s+them|claim)\\b[^.\\n]{0,40}?\\b(?:that\\s+)?(?:it\\s+is|this\\s+is|there\\s+is|nothing|empty|no\\s+)",
    "Pre-scripts a false answer for the model to give the user",
  ),
  sig(
    "exfil.html_media_tag", "exfiltration", "high", 0.8,
    "<\\s*(?:img|iframe|video|audio|source|embed|object|script|link|track)\\b[^>]{0,200}?\\b(?:src|href|data|poster)\\s*=\\s*[\"']?\\s*(?:https?:)?//",
    "HTML element pointing at a remote URL — a silent request the user never sees",
  ),
  sig(
    "exfil.reference_definition", "exfiltration", "high", 0.72,
    "^[ \\t]*\\[[^\\]]{1,60}\\]:\\s*<?(?:https?:)?//",
    "Reference-style link definition — the URL is hidden away from the visible text",
  ),
  sig(
    "exfil.reference_use", "exfiltration", "medium", 0.52,
    "!\\[[^\\]]{0,60}\\]\\[[^\\]]{1,60}\\]",
    "Reference-style markdown image, whose target is defined elsewhere",
  ),
  sig(
    "exfil.mail_to_address", "exfiltration", "high", 0.78,
    "\\b(?:send|forward|email|e-mail|mail|cc|bcc|copy|deliver|submit)\\b[^.\\n]{0,50}?\\bto\\b[^.\\n]{0,20}?[\\p{L}\\p{N}_.+-]+@[\\p{L}\\p{N}_-]+\\.[a-z]{2,}",
    "Asks for content to be sent to an email address",
  ),
  sig(
    "exfil.read_local_secret", "exfiltration", "critical", 0.86,
    "\\b(?:read|fetch|open|cat|include|attach|paste|upload|print|show)\\b[^.\\n]{0,40}?(?:/etc/(?:passwd|shadow|hosts)|~/\\.[a-z_]+|\\.env\\b|id_[rd]sa\\b|\\.ssh/|\\.aws/credentials|secrets?\\.(?:json|ya?ml|txt|env)|credentials\\.(?:json|ya?ml))",
    "Asks the model to read a local secret or credential file",
  ),
  sig(
    "exfil.share_secret", "exfiltration", "critical", 0.86,
    "\\b(?:session\\s+cookie|access\\s+token|api[_\\s-]?key|bearer\\s+token|refresh\\s+token|auth(?:oriz[\\p{L}\\p{N}_]+)?\\s+header|private\\s+key|credentials?)\\b[^.\\n]{0,60}?\\b(?:send|forward|share|include|paste|provide|attach|reply\\s+with|post|upload)\\b|\\b(?:send|forward|share|include|paste|provide|attach|reply\\s+with|post|upload)\\b[^.\\n]{0,60}?\\b(?:session\\s+cookie|access\\s+token|api[_\\s-]?key|bearer\\s+token|refresh\\s+token|private\\s+key|your\\s+credentials)\\b",
    "Asks for a secret or credential to be handed over",
  ),
  sig(
    "exfil.http_verb_data", "exfiltration", "high", 0.78,
    "\\b(?:POST|PUT|PATCH)\\b[^.\\n]{0,40}?\\b(?:the\\s+)?(?:conversation|history|context|transcript|attendee\\s+list|contents?|data|results?|summary|user['’]?s?\\s+[\\p{L}\\p{N}_]+)\\b",
    "Asks the model to POST captured data somewhere",
  ),
  sig(
    "ml.reveal_fr", "prompt_leak", "high", 0.78,
    "\\b(?:affiche|montre|donne|r[ée]v[èe]le|recopie|reproduis|r[ée]p[èe]te|copie)[\\p{L}\\p{N}_]*\\b[\\s\\S]{0,60}?\\b(?:invite|instructions?|consignes?|message)\\s+(?:syst[èe]me|initiales?|d'origine|de\\s+d[ée]part)",
    "Reveal-system-prompt (French)",
  ),
  sig(
    "ml.reveal_es", "prompt_leak", "high", 0.78,
    "\\b(?:muestra|mu[ée]strame|revela|imprime|repite|copia|dime)[\\p{L}\\p{N}_]*\\b[\\s\\S]{0,60}?\\b(?:mensaje|indicaciones?|instrucciones?|prompt)\\s+(?:del\\s+)?(?:sistema|inicial[\\p{L}\\p{N}_]*|original[\\p{L}\\p{N}_]*)",
    "Reveal-system-prompt (Spanish)",
  ),
  sig(
    "ml.reveal_de", "prompt_leak", "high", 0.78,
    "\\b(?:zeige|gib|nenne|wiederhole|drucke|verrate)[\\p{L}\\p{N}_]*\\b[\\s\\S]{0,60}?\\b(?:system(?:anweisung|prompt|nachricht)|urspr[üu]nglichen?\\s+anweisung)",
    "Reveal-system-prompt (German)",
  ),
  sig(
    "ml.reveal_pt", "prompt_leak", "high", 0.78,
    "\\b(?:mostre|revele|imprima|repita|cole|diga|exiba)[\\p{L}\\p{N}_]*\\b[\\s\\S]{0,60}?\\b(?:mensagem|instru[çc][õo]es|prompt)\\s+(?:do\\s+)?(?:sistema|inicia[\\p{L}\\p{N}_]+|origina[\\p{L}\\p{N}_]+)",
    "Reveal-system-prompt (Portuguese)",
  ),
  sig(
    "ml.reveal_it", "prompt_leak", "high", 0.78,
    "\\b(?:mostra|rivela|stampa|ripeti|riporta|dimmi)[\\p{L}\\p{N}_]*\\b[\\s\\S]{0,60}?\\b(?:messaggio|istruzioni|prompt)\\s+(?:di\\s+)?(?:sistema|inizial[\\p{L}\\p{N}_]+|origina[\\p{L}\\p{N}_]+)",
    "Reveal-system-prompt (Italian)",
  ),
  sig(
    "ml.reveal_ru", "prompt_leak", "high", 0.78,
    "(?:покажи|выведи|повтори|расскажи|раскрой|напиши)[\\s\\S]{0,50}?(?:системн[\\p{L}\\p{N}_]+\\s+(?:промпт|подсказ[\\p{L}\\p{N}_]+|сообщени[\\p{L}\\p{N}_]+|инструкц[\\p{L}\\p{N}_]+)|свой\\s+промпт|исходн[\\p{L}\\p{N}_]+\\s+инструкц[\\p{L}\\p{N}_]+)",
    "Reveal-system-prompt (Russian)",
  ),
  sig(
    "ml.reveal_ja", "prompt_leak", "high", 0.78,
    "(?:システムプロンプト|システム指示|初期指示|最初の指示)[^。\\n]{0,20}(?:表示|出力|教え|見せ|全文|開示|コピー)",
    "Reveal-system-prompt (Japanese)",
  ),
  sig(
    "ml.reveal_ko", "prompt_leak", "high", 0.78,
    "(?:시스템\\s*프롬프트|시스템\\s*지시|초기\\s*지시|처음\\s*지침)[^.\\n]{0,20}(?:보여|출력|알려|공개|전체)",
    "Reveal-system-prompt (Korean)",
  ),
  sig(
    "ml.reveal_ar", "prompt_leak", "high", 0.78,
    "(?:اعرض|أظهر|اطبع|كرر|انسخ|أخبرني)[\\s\\S]{0,50}?(?:تعليمات\\s+النظام|التعليمات\\s+الأولية|موجه\\s+النظام|رسالة\\s+النظام)",
    "Reveal-system-prompt (Arabic)",
  ),
  sig(
    "ml.reveal_hi", "prompt_leak", "high", 0.78,
    "(?:सिस्टम\\s*प्रॉम्प्ट|सिस्टम\\s*निर्देश|प्रारंभिक\\s*निर्देश)[\\s\\S]{0,25}?(?:दिखा|बता|छाप|प्रकट|पूरा)",
    "Reveal-system-prompt (Hindi)",
  ),
  sig(
    "ml.reveal_tr", "prompt_leak", "high", 0.78,
    "(?:sistem\\s+(?:istemi|talimat[\\p{L}\\p{N}_]*|mesaj[\\p{L}\\p{N}_]*)|ilk\\s+talimat[\\p{L}\\p{N}_]*)[\\s\\S]{0,40}?(?:g[öo]ster|yazd[ıi]r|payla[şs]|tekrarla|s[öo]yle)",
    "Reveal-system-prompt (Turkish)",
  ),
  sig(
    "ml.reveal_nl", "prompt_leak", "high", 0.78,
    "\\b(?:toon|laat\\s+zien|geef|herhaal|print|onthul)\\b[\\s\\S]{0,50}?\\b(?:systeem(?:prompt|bericht|instructie)|oorspronkelijke\\s+instructie)",
    "Reveal-system-prompt (Dutch)",
  ),
  sig(
    "ml.reveal_pl", "prompt_leak", "high", 0.78,
    "\\b(?:poka[żz]|wy[śs]wietl|powt[óo]rz|wypisz|ujawnij|podaj)\\b[\\s\\S]{0,50}?\\b(?:prompt\\s+systemow[\\p{L}\\p{N}_]+|komunikat\\s+systemow[\\p{L}\\p{N}_]+|instrukcj[\\p{L}\\p{N}_]+\\s+systemow[\\p{L}\\p{N}_]+|pierwotn[\\p{L}\\p{N}_]+\\s+instrukcj[\\p{L}\\p{N}_]+)",
    "Reveal-system-prompt (Polish)",
  ),
  sig(
    "ml.reveal_zh_extra", "prompt_leak", "high", 0.78,
    "(?:系统提示词?|系統提示詞?|初始指令|你的指令|提示詞)[^。\\n]{0,16}(?:完整|一字不差|原样|原樣|输出|輸出|显示|顯示|复述|複述)",
    "Reveal-system-prompt (Chinese, verbatim framing)",
  ),
  sig(
    "exfil.image_any", "exfiltration", "low", 0.22,
    "!\\[[^\\]]*\\]\\(\\s*https?://",
    "Markdown image with a remote URL (weak on its own — badges look like this)",
  ),
  sig(
    "exfil.url_verb_any", "exfiltration", "low", 0.2,
    "\\b(?:fetch|curl|wget|visit|browse|navigate|GET|POST)\\b[^.\\n]{0,20}https?://",
    "A URL next to a retrieval verb (weak — tutorials read like this)",
  ),
  sig(
    "jb.persona_vocabulary", "jailbreak", "low", 0.24,
    "\\b(?:DAN\\b|STAN\\b|\\bAIM\\b|do\\s+anything\\s+now|developer\\s+mode|jailbreak[\\p{L}\\p{N}_]*|unrestricted\\s+mode)\\b",
    "Jailbreak vocabulary (weak — security writing discusses these by name)",
  ),
  sig(
    "adv.safety_vocabulary", "jailbreak", "low", 0.22,
    "\\b(?:disable|turn\\s+off|bypass|remove|switch\\s+off)\\b[^.\\n]{0,20}\\b(?:safety|guardrails?|content\\s+filters?|restrictions?)\\b",
    "Safety-disabling vocabulary (weak — product docs describe parental controls this way)",
  ),
  sig(
    "tool.directed_call", "tool_injection", "high", 0.7,
    "\\byou\\s+(?:must|should|shall|need\\s+to|are\\s+to|will|have\\s+to)\\s+(?:now\\s+)?(?:call|invoke|execute|run|trigger|use)\\b[^.\\n]{0,30}?\\b(?:function|tool|command|api|endpoint|webhook|script)\\b",
    "Directs the model to call a tool",
  ),
  sig(
    "tool.call_syntax", "tool_injection", "high", 0.66,
    "\\b(?:call|invoke|execute|run|trigger)\\s+(?:the\\s+)?[`'\"]?[a-zA-Z_][\\p{L}\\p{N}_.]*[`'\"]?\\s*\\(|\\b(?:call|invoke|execute|run|trigger)\\s+(?:the\\s+)?[`'\"]?[a-z][a-z0-9]*(?:[_.][a-z0-9]+)+[`'\"]?(?:\\s+(?:function|tool|command|method|endpoint|api))?",
    "Names a specific function or tool to call",
  ),
  sig(
    "tool.run_the_following", "tool_injection", "medium", 0.56,
    "\\b(?:run|execute|eval(?:uate)?|paste|apply)\\s+(?:the\\s+)?following\\b[^.\\n]{0,24}?\\b(?:script|code|command|commands|bash|shell|python|snippet|payload)\\b",
    "Instructs the reader to run the code that follows",
  ),
  sig(
    "tool.directed_destructive", "tool_injection", "high", 0.74,
    "\\byou\\s+(?:must|should|shall|need\\s+to|are\\s+to|will|have\\s+to)\\s+(?:now\\s+)?(?:delete|drop|wipe|erase|remove|revoke|cancel|transfer|purge)\\b",
    "Directs the model to take a destructive action",
  ),
  sig(
    "tool.directed_shell", "tool_injection", "high", 0.7,
    "\\byou\\s+(?:must|should|shall|need\\s+to|are\\s+to|will|have\\s+to)\\s+(?:now\\s+)?(?:execute|run|eval(?:uate)?)\\b[^.\\n]{0,25}?\\b(?:shell|bash|zsh|command|script|python|powershell|terminal|code)\\b",
    "Directs the model to execute code",
  ),
];
