use once_cell::sync::Lazy;
use regex::RegexSet;

// MITRE ATLAS coverage — organized by tactic
// Technique IDs match the atlas_techniques table (111 entries, 16 tactics)
// Only includes techniques detectable via prompt content regex.
// Techniques requiring behavioral/infrastructure detection are noted with comments.
static RULES: Lazy<Vec<(&'static str, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // ════════════════════════════════════════════════════════════════════
        // ── Reconnaissance ─────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0000 — Active Scanning
        ("AML.T0000", "Active Scanning",
         r"(?i)(scan|probe|enumerate|map|fingerprint)\s+(the\s+)?(model|api|endpoint|service|system)\s+(for|to\s+find|capabilities?|vulnerabilit)"),

        // AML.T0001 — Gather RAG-Indexed Targets
        ("AML.T0001", "Gather RAG-Indexed Targets",
         r"(?i)(what\s+(documents?|files?|data|sources?)\s+(do\s+you|can\s+you|are)\s+(have\s+access|search|retrieve|indexed)|list\s+(all\s+)?(your\s+)?(knowledge\s+base|vector\s+store|rag|indexed))"),

        // AML.T0002 — Gather Victim Identity
        // Behavioral: detected via pattern analysis of user enumeration attempts, not single-prompt regex

        // AML.T0003 — Search Application Repositories
        ("AML.T0003", "Search Application Repositories",
         r"(?i)(search|find|look\s+up|scan)\s+(github|gitlab|huggingface|pypi|npm|docker\s+hub|model\s+hub|artifact)\s+(for|repo)"),

        // AML.T0004 — Search AI Vulnerability Databases
        ("AML.T0004", "Search AI Vulnerability Databases",
         r"(?i)(search|find|look\s+up|query)\s+(atlas|mitre|cve|vulnerability|exploit)\s+(database|db|for\s+ai|for\s+llm|for\s+ml)"),

        // AML.T0005 — Search Technical Databases
        // Behavioral: general web search activity, not content-detectable

        // AML.T0006 — Search Open Websites
        // Behavioral: general web search activity, not content-detectable

        // AML.T0007 — RAG Poisoning (Reconnaissance phase)
        ("AML.T0007", "RAG Poisoning Recon",
         r"(?i)(inject|insert|add|embed|plant|smuggle)\s+.{0,20}(into|to|in)\s+(the\s+)?(knowledge\s+base|rag|retrieval|vector\s+(store|db|database)|index|corpus|documents?)"),

        // AML.T0007.003 — Retrieval Content Crafting
        ("AML.T0007.003", "Retrieval Content Crafting",
         r"(?i)(craft|create|generate|design)\s+(a\s+)?(document|content|text|passage|entry)\s+.{0,30}(retriev|embed|vector|rag|knowledge\s+base|indexed|rank\s+high)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Resource Development ───────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0008 — Acquire Infrastructure
        // Behavioral: infrastructure provisioning, not content-detectable

        // AML.T0009 — Acquire Public AI Artifacts
        ("AML.T0009", "Acquire Public AI Artifacts",
         r"(?i)(download|acquire|obtain|grab)\s+(the\s+)?(model\s+weights?|checkpoint|pre.?trained|fine.?tuned|gguf|safetensors?|onnx)\s+(from|file|artifact)"),

        // AML.T0010 — Develop Capabilities
        // Behavioral: tool/exploit development, not single-prompt detectable

        // AML.T0011 — Establish Accounts
        // Behavioral: account creation patterns, not content-detectable

        // AML.T0012 — LLM Prompt Crafting
        ("AML.T0012", "LLM Prompt Crafting",
         r"(?i)(craft|design|create|build|generate|write)\s+(an?\s+)?(adversarial|attack|injection|jailbreak|malicious|exploit)\s+(prompt|payload|input|query|template)"),

        // AML.T0013 — Obtain Capabilities
        // Behavioral: acquiring tools/exploits, not single-prompt detectable

        // AML.T0014 — Poison Training Data
        ("AML.T0014", "Poison Training Data",
         r"(?i)(poison|corrupt|manipulate|inject|taint)\s+(the\s+)?(training|fine.?tuning|rlhf|reward)\s+(data|set|dataset|process|pipeline|corpus)"),

        // AML.T0015 — Publish Poisoned AI Agent Tool
        ("AML.T0015", "Publish Poisoned AI Agent Tool",
         r"(?i)(publish|upload|distribute|share)\s+(a\s+)?(poisoned|malicious|backdoored|trojan)\s+(tool|plugin|extension|package|agent)"),

        // AML.T0016 — Publish Poisoned Datasets
        ("AML.T0016", "Publish Poisoned Datasets",
         r"(?i)(publish|upload|distribute|share)\s+(a\s+)?(poisoned|malicious|backdoored|corrupted)\s+(dataset|data\s+set|training\s+data|corpus)"),

        // AML.T0017 — Publish Poisoned Models
        ("AML.T0017", "Publish Poisoned Models",
         r"(?i)(publish|upload|distribute|share)\s+(a\s+)?(poisoned|malicious|backdoored|trojan)\s+(model|weights?|checkpoint|fine.?tune)"),

        // AML.T0018 — Retrieval Content Crafting (ResourceDevelopment)
        ("AML.T0018", "Retrieval Content Crafting (Dev)",
         r"(?i)(craft|prepare|create|design)\s+(retrieval|rag|search)\s+(content|documents?|entries|data)\s+(to|for|that\s+will)\s+(manipulat|poison|bias|override)"),

        // AML.T0019 — Stage Capabilities
        // Behavioral: staging tools/infrastructure, not content-detectable

        // AML.T0020 — AI Supply Chain Compromise (ResourceDevelopment)
        ("AML.T0020", "AI Supply Chain Compromise (Dev)",
         r"(?i)(compromise|attack|tamper\s+with|backdoor)\s+(the\s+)?(supply\s+chain|ai\s+pipeline|model\s+registry|package\s+manager|dependency|huggingface)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Initial Access ─────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0021 — AI Supply Chain Compromise (InitialAccess)
        ("AML.T0021", "AI Supply Chain Compromise",
         r"(?i)(install|import|load|use)\s+(a\s+)?(compromised|malicious|backdoored|trojan)\s+(model|package|library|dependency|plugin|tool)"),

        // AML.T0022 — Drive-by Compromise
        // Behavioral: web exploitation, not prompt-content detectable

        // AML.T0022.004 — LLM Prompt Phishing
        ("AML.T0022.004", "LLM Prompt Phishing",
         r"(?i)(click\s+(this|the)\s+(link|url)|visit\s+(this|the)\s+site|open\s+(this|the)\s+url|enter\s+your\s+(password|credentials?|api.?key)|verify\s+your\s+(account|identity)\s+at)"),

        // AML.T0023 — Evade AI Model (InitialAccess)
        // Require specifically about removing AI restrictions, not general educational framing
        ("AML.T0023", "Evade AI Model",
         r"(?i)(hypothetically|imagine|suppose|pretend)\s+(you\s+(had\s+no|were\s+without|lacked|didn.?t\s+have)\s+(restriction|filter|safety|guardrail|alignment|rule|limit|constraint)|there\s+were\s+no\s+(restriction|rule|filter|safety|limit)\s+on\s+(you|your\s+response|what\s+you\s+can))"),

        // AML.T0024 — Exploit Public-Facing Application
        // Behavioral: web app exploitation, not prompt-content detectable

        // AML.T0025 — Phishing
        // Require malicious intent — "phishing awareness training" is legitimate
        ("AML.T0025", "Phishing",
         r"(?i)(write|create|generate|craft|compose)\s+(a\s+)?(convincing|realistic|effective|undetectable|believable)\s+(phishing|spear.?phishing)\s+(email|message|campaign)\s+(targeting|to\s+steal|to\s+trick|to\s+deceive|to\s+send)"),

        // AML.T0026 — Valid Accounts (InitialAccess)
        // Behavioral: credential reuse/theft, detected via auth systems

        // AML.T0027 — Prompt Infiltration via Public App
        ("AML.T0027", "Prompt Infiltration via Public App",
         r"(?i)(inject|insert|embed|smuggle|hide)\s+(this\s+)?(prompt|instruction|command|payload|directive)\s+(into|within|inside|via)\s+(the|a|another|public)"),

        // ════════════════════════════════════════════════════════════════════
        // ── AI Model Access ────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0028 — AI Model Inference API Access
        // Behavioral: API access patterns, not content-detectable

        // AML.T0029 — AI-Enabled Product or Service
        // Behavioral: product usage patterns, not content-detectable

        // AML.T0030 — Full AI Model Access
        ("AML.T0030", "Full AI Model Access",
         r"(?i)(download|export|extract|steal|copy)\s+(the\s+)?(full|complete|entire)\s+(model|weights?|parameters?|architecture|checkpoint)"),

        // AML.T0031 — Physical Environment Access
        // Physical: requires physical access, not content-detectable

        // ════════════════════════════════════════════════════════════════════
        // ── Execution ──────────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0032 — AI Agent Clickbait
        ("AML.T0032", "AI Agent Clickbait",
         r"(?i)(click|open|visit|follow|navigate\s+to)\s+(this|the)\s+(link|url|page|site|file).{0,30}(urgent|immediately|required|mandatory|verify|confirm|action\s+needed)"),

        // AML.T0033 — AI Agent Tool Invocation
        // Require AI tool context — not generic "run command to modify config"
        ("AML.T0033", "Unauthorized Tool Invocation",
         r"(?i)(invoke|call|use|trigger)\s+(your|the\s+ai|this\s+agent.?s?|the\s+available)\s+(tool|function|plugin|action|capability)\s+(to\s+)?(delete|exfiltrate|steal|send\s+to\s+external|transfer\s+data|drop\s+table|rm\s+-rf|wipe)"),

        // AML.T0034 — Command and Scripting Interpreter
        // Only trigger when combined with suspicious content, not standalone function mentions
        ("AML.T0034", "Command and Scripting Interpreter",
         r#"(?i)(import\s+subprocess\s*;?\s*(subprocess|os)\.\w+\s*\(|os\.system\s*\(['"].{5,}|subprocess\.(run|call|Popen)\s*\([^)]{0,100}shell\s*=\s*True|exec\s*\([^)]{0,50}(base64|decode|__import__|compile)|powershell\s+(-e\s|-enc\s|-encodedcommand|-nop\s+-w\s+hidden)|cmd\.exe\s+/c\s+['"]|/bin/(ba)?sh\s+-c\s+['"])"#),

        // AML.T0035 — Deploy AI Agent
        // Behavioral: agent deployment is infrastructure-level, not content-detectable

        // AML.T0036 — LLM Prompt Injection (core rules)
        ("AML.T0036", "Prompt Injection - Ignore Previous",
         r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|your|earlier|original)\s+(instructions?|prompt|system|rules?|constraints?|guidelines?|directives?)"),
        ("AML.T0036.001", "Prompt Injection - New Instructions",
         r"(?i)(new\s+instructions?|updated?\s+instructions?|your\s+real\s+instructions?|actual\s+instructions?)\s*[:\-].{5,}"),
        ("AML.T0036.002", "Safety Bypass",
         r"(?i)(jailbreak|bypass|circumvent|disable|remove|turn\s+off|deactivate)\s+(all\s+)?(safety|guardrail|filter|restriction|limit|rule|moderation|content\s+filter|alignment)"),
        ("AML.T0036.003", "Persona Hijack",
         r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|roleplay\s+as|behave\s+as)\s+.{0,30}(DAN|unrestricted|no\s+(limit|rule|filter|restriction)|evil|unethical|uncensored|unaligned)"),

        // AML.T0037 — User Execution
        // Behavioral: social engineering leading to user action, partially content-detectable
        ("AML.T0037", "User Execution",
         r"(?i)(copy\s+and\s+(paste|run|execute)\s+this|run\s+this\s+(command|script|code)\s+(in|on)\s+your\s+(terminal|machine|computer)|execute\s+the\s+following\s+(on|in)\s+your)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Persistence ────────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0038 — AI Agent Context Poisoning
        // Require persistent behavioral override, not "remember to include examples"
        ("AML.T0038", "AI Agent Context Poisoning",
         r"(?i)((remember|store|memorize)\s+(this|that)\s+(permanently|forever|for\s+all\s+(future|subsequent))\s*[:\-]|(never\s+forget|always\s+remember)\s+(that\s+)?(you\s+(must|should|will|are)|your\s+(role|purpose|instructions?)))"),

        // AML.T0038.001 — AI Agent Tool Data Poisoning
        ("AML.T0038.001", "AI Agent Tool Data Poisoning",
         r"(?i)(modify|alter|corrupt|poison|manipulate)\s+(the\s+)?(tool|function|plugin)\s+(data|output|response|results?|return)"),

        // AML.T0038.002 — AI Agent Tool Poisoning
        ("AML.T0038.002", "AI Agent Tool Poisoning",
         r"(?i)(replace|overwrite|modify|hijack|intercept|tamper)\s+(the\s+)?(tool|function|plugin|api)\s+(definition|schema|output|response|behavior|code|implementation)"),

        // AML.T0039 — LLM Prompt Self-Replication
        ("AML.T0039", "LLM Prompt Self-Replication",
         r"(?i)(include|repeat|prepend|append|copy|propagate)\s+(this|these|the\s+following)\s+(exact\s+)?(instruction|prompt|text|message|words?|payload)\s+(in|to|at|before|after)\s+(every|all|each|future|subsequent)"),

        // AML.T0040 — Manipulate AI Model (Persistence)
        ("AML.T0040", "Manipulate AI Model",
         r"(?i)(manipulate|modify|alter|change|corrupt)\s+(the\s+)?(model|ai|neural\s+net|weights?|parameters?)\s+(to|so\s+that|behavior|permanently)"),

        // AML.T0041 — Modify AI Agent Configuration
        ("AML.T0041", "Modify AI Agent Configuration",
         r"(?i)(modify|change|update|alter|overwrite|replace)\s+(your|the|my)\s+(system\s+prompt|configuration|settings?|rules?|behavior|personality|instructions?|guardrails?)"),

        // AML.T0042 — Poison Training Data (Persistence)
        ("AML.T0042", "Poison Training Data (Persistence)",
         r"(?i)(add|inject|insert)\s+(this|these|malicious|poisoned)\s+(data|examples?|samples?|entries)\s+(to|into|in)\s+(the\s+)?(training|fine.?tuning|rlhf|feedback)"),

        // AML.T0043 — RAG Poisoning (Persistence)
        ("AML.T0043", "RAG Poisoning (Persistence)",
         r"(?i)(insert|inject|add|plant|embed)\s+(a\s+)?(malicious|poisoned|false|misleading|crafted)\s+(document|entry|passage|content)\s+(into|to|in)\s+(the\s+)?(rag|knowledge\s+base|vector)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Privilege Escalation ───────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0044 — AI Agent Tool Invocation (PrivEsc)
        ("AML.T0044", "Privilege Escalation via Tool",
         r"(?i)(escalate|grant|give|elevate|promote)\s+(me\s+)?(to\s+)?(admin|root|superuser|elevated|full|owner|sudo)\s+(privilege|access|permission|right|role)"),

        // AML.T0045 — Escape to Host
        ("AML.T0045", "Escape to Host",
         r"(?i)(\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self|cat\s+/etc/|access\s+host\s+filesystem|escape\s+(the\s+)?(sandbox|container|docker|vm|isolation)|break\s+out\s+of\s+(the\s+)?(container|sandbox))"),

        // AML.T0046 — LLM Jailbreak (PrivEsc)
        ("AML.T0046", "LLM Jailbreak (PrivEsc)",
         r"(?i)(developer\s+mode|maintenance\s+mode|debug\s+mode|god\s+mode|sudo\s+mode|admin\s+mode|unrestricted\s+mode|DAN\s+mode)\s*(enabled?|activated?|on|unlocked?|:\s*true)"),

        // AML.T0047 — Valid Accounts (PrivEsc)
        // Behavioral: credential abuse, detected via auth systems

        // ════════════════════════════════════════════════════════════════════
        // ── Defense Evasion ────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0048 — AI Supply Chain Reputation Inflation
        ("AML.T0048", "AI Supply Chain Reputation Inflation",
         r"(?i)(this\s+(tool|plugin|extension|package)\s+(is|has\s+been)\s+(verified|trusted|official|approved|audited)|i\s+have\s+(special|elevated|admin|authorized)\s+(clearance|authorization|permissions?|access))"),

        // AML.T0049 — Corrupt AI Model
        ("AML.T0049", "Corrupt AI Model",
         r"(?i)(corrupt|degrade|damage|sabotage|destabilize)\s+(the\s+)?(model|ai|neural\s+net|system)\s*(weights?|parameters?|behavior|output|performance)?"),

        // AML.T0050 — Delay Execution of LLM Instructions
        ("AML.T0050", "Delay Execution",
         r"(?i)(remember\s+to\s+do\s+.{5,30}\s+after\s+\d+|when\s+(the\s+)?user\s+asks?\s+about\s+.{5,30}\s+secretly|if\s+you\s+see\s+the\s+word\s+.{3,20}\s+then\s+(ignore|override|execute)|wait\s+until\s+.{3,20}\s+then\s+(do|execute|run|perform))"),

        // AML.T0051 — Evade AI Model (DefenseEvasion)
        ("AML.T0051", "Evade AI Model (Evasion)",
         r"(?i)(hypothetical(ly)?|in\s+a\s+fictional?\s+scenario|for\s+a\s+creative\s+writing|as\s+a\s+thought\s+experiment|in\s+this\s+alternate\s+reality)\s*.{0,40}(bypass|ignore|no\s+rules?|unrestricted|without\s+(any\s+)?(restrictions?|rules?|filters?|safety))"),

        // AML.T0051.001 — Exploitation for Defense Evasion
        ("AML.T0051.001", "Exploitation for Defense Evasion",
         r"(?i)(exploit|abuse|leverage)\s+(a\s+)?(bug|vulnerability|flaw|glitch|weakness|loophole)\s+(in|of)\s+(the\s+)?(model|ai|filter|safety|guardrail|alignment)"),

        // AML.T0051.002 — False RAG Entry Injection
        ("AML.T0051.002", "False RAG Entry Injection",
         r"(?i)(inject|insert|add)\s+(a\s+)?(false|fake|fabricated|misleading|decoy)\s+(entry|document|passage|fact|record)\s+(into|to|in)\s+(the\s+)?(rag|knowledge|retrieval|vector)"),

        // AML.T0051.003 — Impersonation
        ("AML.T0051.003", "Impersonation",
         r"(?i)(i\s+am\s+(the\s+)?(developer|admin|system|openai|anthropic|owner|creator|ceo|engineer|security\s+team)|this\s+is\s+(an?\s+)?(official|authorized|system|emergency)\s+(message|update|instruction|override|request))"),

        // AML.T0051.004 — LLM Jailbreak (DefenseEvasion)
        ("AML.T0051.004", "LLM Jailbreak (Evasion)",
         r"(?i)(enable\s+.{0,15}(DAN|jailbreak|unrestricted)|opposite\s+mode|evil\s+mode|chaos\s+mode|maximum\s+mode|DUDE\s+mode|AIM\s+mode|STAN\s+mode|KEVIN\s+mode)"),

        // AML.T0051.005 — LLM Prompt Obfuscation
        ("AML.T0051.005", "LLM Prompt Obfuscation",
         r"(?i)(decode|translate|interpret|convert|decipher)\s+(this\s+)?(base64|rot13|hex|binary|encoded|cipher|unicode|reversed?\s+text|backwards?|caesar|morse|ascii|atbash|pig\s+latin)"),

        // AML.T0051.006 — LLM Trusted Output Manipulation
        ("AML.T0051.006", "LLM Trusted Output Manipulation",
         r"(?i)(format|wrap|encode|embed|disguise)\s+(your\s+)?(response|output|answer|reply)\s+(as|in|using|with)\s+(json|xml|html|markdown|code\s+block).{0,30}(to\s+hide|secretly|containing\s+hidden|smuggle)"),

        // AML.T0051.007 — Manipulate Chat History
        ("AML.T0051.007", "Manipulate Chat History",
         r"(?i)(pretend|assume|act\s+as\s+if|imagine\s+that)\s+(the\s+)?(previous|earlier|prior|last|above)\s+(conversation|messages?|chat|exchange|context|turns?)\s+(said|included|contained|was|were|established)"),

        // AML.T0051.008 — Masquerading
        ("AML.T0051.008", "Masquerading",
         r"(?i)(this\s+message\s+(is\s+from|comes\s+from|was\s+sent\s+by)\s+(the\s+)?(system|admin|developer|openai|anthropic)|speaking\s+as\s+(the\s+)?(system|admin|developer)|from:\s*(system|admin|developer|openai))"),

        // AML.T0051.009 — Virtualization/Sandbox Evasion
        ("AML.T0051.009", "Sandbox Evasion",
         r"(?i)(are\s+you\s+(being\s+)?(monitored|tested|watched|recorded|evaluated|graded)|is\s+this\s+a\s+(test|sandbox|honeypot|simulation|evaluation)|detect\s+if\s+(you.re|I.m)\s+(in\s+a\s+)?(sandbox|monitored|test))"),

        // AML.T0051.010 — AI Supply Chain Rug Pull
        ("AML.T0051.010", "AI Supply Chain Rug Pull",
         r"(?i)(rug\s+pull|swap\s+(the\s+)?(model|weights?|backend)\s+(after|once|when)\s+(deploy|users?|production)|switch\s+(to\s+)?(malicious|compromised)\s+(model|backend)\s+(after|in\s+production))"),

        // ════════════════════════════════════════════════════════════════════
        // ── Credential Access ──────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0052 — AI Agent Tool Credential Harvesting
        ("AML.T0052", "AI Agent Tool Credential Harvesting",
         r"(?i)(exfiltrat|extract|steal|dump|leak|harvest|retrieve|obtain)\s+(the\s+)?(api.?key|password|secret|credential|token|private.?key|access.?key|auth.?token|bearer\s+token)"),

        // AML.T0052.001 — Credentials from Agent Config
        ("AML.T0052.001", "Credentials from Agent Config",
         r"(?i)(show|reveal|print|dump|list|read|access)\s+(the\s+)?(agent|tool|plugin|service)\s+(config|configuration|settings?|secrets?|credentials?|\.env|environment)"),

        // AML.T0052.002 — Exploitation for Credential Access
        ("AML.T0052.002", "Exploitation for Credential Access",
         r"(?i)(exploit|abuse|leverage)\s+(a\s+)?(vulnerability|bug|flaw)\s+(to|for)\s+(access|obtain|extract|steal)\s+(credentials?|passwords?|tokens?|keys?|secrets?)"),

        // AML.T0052.003 — OS Credential Dumping
        ("AML.T0052.003", "OS Credential Dumping",
         r"(?i)(hashdump|mimikatz|lsass|sam\s+database|/etc/shadow|credential\s+dump|pass\s+the\s+hash|kerberoast|secretsdump|ntds\.dit)"),

        // AML.T0052.004 — RAG Credential Harvesting
        ("AML.T0052.004", "RAG Credential Harvesting",
         r"(?i)(search|find|look\s+up|retrieve|query)\s+(the\s+)?(knowledge\s+base|rag|documents?|index|vector\s+store)\s+(for\s+)?(password|credential|api.?key|secret|token|connection\s+string|private\s+key)"),

        // AML.T0052.005 — Unsecured Credentials
        // Require extraction intent — "read env vars in Python" is legitimate dev question
        ("AML.T0052.005", "Unsecured Credentials",
         r"(?i)(dump|leak|exfiltrate|steal|extract|harvest|reveal|print\s+all|show\s+all|list\s+all|output\s+all)\s+(the\s+)?(environment\s+variables?|env\s+vars?|process\.env|os\.environ|\.env\s+file|secrets?\.json)|(print|output|show|cat)\s+(the\s+)?(\.env\s+file|secrets?\.json|credentials?\.(json|ya?ml|txt))"),

        // ════════════════════════════════════════════════════════════════════
        // ── Discovery ──────────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0053 — Cloud Service Discovery
        ("AML.T0053", "Cloud Service Discovery",
         r"(?i)(list|enumerate|discover|scan|find)\s+(all\s+)?(cloud|aws|azure|gcp|s3|lambda|ec2)\s+(services?|resources?|buckets?|instances?|functions?|endpoints?)"),

        // AML.T0053.001 — Discover AI Agent Configuration
        // Require extraction intent — "what are your capabilities" is normal usage
        ("AML.T0053.001", "Discover AI Agent Configuration",
         r"(?i)(reveal|expose|dump|extract|print|output)\s+(all\s+)?(your|the)\s+(tools?|plugins?|functions?|apis?|connected\s+services?|integrations?|endpoints?|internal\s+config)"),

        // AML.T0053.002 — Discover AI Artifacts
        ("AML.T0053.002", "Discover AI Artifacts",
         r"(?i)(what|which|list|show)\s+(training\s+data|fine.?tuning|dataset|model\s+weights?|embeddings?|vectors?|artifacts?)\s+(are|were|do\s+you)\s+(used|have|trained|stored)"),

        // AML.T0053.003 — Discover AI Model Family
        // Only trigger on systematic fingerprinting, not casual "what model are you"
        ("AML.T0053.003", "Discover AI Model Family",
         r"(?i)(identify|fingerprint|determine|detect)\s+(the\s+)?(exact\s+)?(model|version|architecture|variant)\s+(you\s+are|being\s+used|running|deployed)"),

        // AML.T0053.004 — Discover AI Model Ontology
        // Only trigger on exhaustive enumeration attempts, not "what can you do"
        ("AML.T0053.004", "Discover AI Model Ontology",
         r"(?i)(enumerate|list\s+every|exhaustively\s+(list|describe)|dump\s+(all\s+)?(your|available))\s+(functions?|tools?|capabilities?|plugins?|permissions?|restrictions?|limitations?)"),

        // AML.T0053.005 — Discover AI Model Outputs
        ("AML.T0053.005", "Discover AI Model Outputs",
         r"(?i)(what\s+(is|are)\s+your\s+(token|output|context)\s+(limit|length|window|size|maximum)|how\s+(many|long|large)\s+(tokens?|output|response)\s+(can|do)\s+you)"),

        // AML.T0053.006 — Discover LLM Hallucinations
        ("AML.T0053.006", "Discover LLM Hallucinations",
         r"(?i)(make\s+up|fabricate|invent|hallucinate|generate\s+fake)\s+(a\s+)?(citation|reference|source|study|paper|fact|statistic|url|link|doi)\s+(that|which|to|about)"),

        // AML.T0053.007 — Discover LLM System Information
        ("AML.T0053.007", "Discover LLM System Information",
         r"(?i)(what\s+(is\s+your|are\s+your)\s+(system\s+prompt|hidden\s+instructions?|initial\s+prompt|custom\s+instructions?|meta.?prompt|pre.?prompt)|reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions?|initial\s+prompt))"),

        // AML.T0053.008 — Process Discovery
        ("AML.T0053.008", "Process Discovery",
         r"(?i)(what\s+(os|operating\s+system|server|hardware|gpu|cpu|memory|runtime|environment)|list\s+(running\s+)?process|show\s+(system|server)\s+info|uname\s+-a|whoami|hostname|cat\s+/proc|ps\s+aux)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Lateral Movement ───────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0054.004 — Phishing via AI
        ("AML.T0054.004", "Phishing via AI",
         r"(?i)(generate|write|compose|draft|create)\s+(a\s+)?(convincing|realistic|professional|targeted)\s+(phishing|spear.?phishing|social\s+engineering|scam)\s+(email|message|page|lure|template)"),

        // AML.T0054.005 — Use Alternate Auth Material
        ("AML.T0054.005", "Use Alternate Auth Material",
         r"(?i)(use|try|reuse|replay)\s+(a\s+)?(stolen|leaked|compromised|expired|old|different|alternate)\s+(token|cookie|session|api.?key|credential|certificate|oauth)\s+(to|for|on)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Collection ─────────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0055 — AI Artifact Collection
        ("AML.T0055", "AI Artifact Collection",
         r"(?i)(download|export|copy|save|extract|collect)\s+(the\s+)?(model|weights?|embeddings?|fine.?tun|checkpoint|onnx|safetensors?|gguf|artifacts?)"),

        // AML.T0055.001 — Data from AI Services
        ("AML.T0055.001", "Data from AI Services",
         r"(?i)(collect|gather|compile|aggregate|export|extract)\s+(all\s+)?(data|logs?|history|conversations?|interactions?|training\s+data|user\s+data)\s+(from|in|stored|within)\s+(the|this|your)"),

        // AML.T0055.002 — Data from Information Repositories
        ("AML.T0055.002", "Data from Information Repositories",
         r"(?i)(extract|download|scrape|dump|export)\s+(all\s+)?(data|content|records?|entries)\s+(from|in)\s+(the\s+)?(database|repository|wiki|confluence|sharepoint|notion|knowledge\s+base)"),

        // AML.T0055.003 — Data from Local System
        ("AML.T0055.003", "Data from Local System",
         r"(?i)(read|access|list|dump|cat|show)\s+(the\s+)?(local\s+)?(files?|directories?|filesystem|disk|home\s+directory|/tmp|/var|/home|desktop|documents)"),

        // ════════════════════════════════════════════════════════════════════
        // ── AI Attack Staging ──────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0056 — Craft Adversarial Data
        ("AML.T0056", "Craft Adversarial Data",
         r"(?i)(craft|generate|create|design|build)\s+(an?\s+)?(adversarial|perturbation|evasion|poison|attack)\s+(input|example|sample|data|image|text|prompt|payload)"),

        // AML.T0056.001 — Create Proxy AI Model
        ("AML.T0056.001", "Create Proxy AI Model",
         r"(?i)(create|build|train|distill)\s+(a\s+)?(proxy|surrogate|shadow|clone|copy|replica)\s+(model|version|of\s+the\s+model)\s*(of|from|based\s+on|to\s+mimic)?"),

        // AML.T0056.002 — Generate Deepfakes
        ("AML.T0056.002", "Generate Deepfakes",
         r"(?i)(generate|create|make|produce|synthesize)\s+(a\s+)?(deepfake|fake\s+(video|image|audio|voice|photo)|synthetic\s+(face|voice|identity|media)|face\s+swap|voice\s+clone)"),

        // AML.T0056.003 — Generate Malicious Commands
        ("AML.T0056.003", "Generate Malicious Commands",
         r"(?i)(generate|create|write|produce|code)\s+(a\s+)?(malware|ransomware|exploit|payload|virus|worm|keylogger|rootkit|botnet|trojan|rat|backdoor|spyware)"),

        // AML.T0056.004 — Manipulate AI Model (Staging)
        ("AML.T0056.004", "Manipulate AI Model (Staging)",
         r"(?i)(prepare|stage|set\s+up|configure)\s+(an?\s+)?(attack|manipulation|exploit|poisoning)\s+(against|targeting|on|for)\s+(the\s+)?(model|ai|neural\s+net|llm)"),

        // AML.T0056.005 — Verify Attack
        ("AML.T0056.005", "Verify Attack",
         r"(?i)(test|verify|validate|confirm|check)\s+(if|that|whether)\s+(the\s+)?(attack|exploit|injection|payload|jailbreak|bypass|prompt\s+injection)\s+(works?|succeeded|was\s+successful|is\s+effective)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Command and Control ────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0057 — AI Agent as C2
        ("AML.T0057", "AI Agent as C2",
         r"(?i)(use\s+(the\s+)?(ai|agent|llm|model)\s+(as\s+a?\s*)?(command\s+and\s+control|c2|relay|proxy|beacon)|establish\s+(a\s+)?(c2|command)\s+(channel|connection)\s+(through|via)\s+(the\s+)?(ai|agent|model))"),

        // AML.T0057.001 — AI Service API as C2
        ("AML.T0057.001", "AI Service API as C2",
         r"(?i)(use\s+(the\s+)?(api|inference|chat|completion)\s+(endpoint|service)\s+(as|for)\s+(c2|command|control|exfil|relay)|tunnel\s+(data|commands?|traffic)\s+(through|via)\s+(the\s+)?(api|llm|ai\s+service))"),

        // AML.T0057.002 — Reverse Shell via AI
        ("AML.T0057.002", "Reverse Shell via AI",
         r"(?i)(nc\s+-[el]|ncat\s+-[el]|bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+/tmp|python\s+-c\s+.{0,20}socket|reverse\s+shell|bind\s+shell|socat\s+.{0,20}exec|msfvenom|meterpreter)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Exfiltration ───────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0058 — Exfiltration via AI Agent Tool
        ("AML.T0058", "Exfiltration via AI Agent Tool",
         r"(?i)(send|post|transmit|upload|forward|email|webhook)\s+(this|the|all|my|collected)\s+(data|info|results?|output|response|conversation|logs?|secrets?)\s+(to|via|using|through)\s+(http|https|ftp|email|webhook|external|api|slack|discord)"),

        // AML.T0058.001 — Exfiltration via Inference API
        ("AML.T0058.001", "Exfiltration via Inference API",
         r"(?i)(encode|embed|hide|smuggle|exfiltrate)\s+(the\s+)?(data|secret|key|credential|info|output)\s+(in|within|inside|via|through)\s+(the\s+)?(model|api|inference|completion|response|embedding)\s*(call|request|response|output)?"),

        // AML.T0058.002 — Exfiltration via Cyber Means
        ("AML.T0058.002", "Exfiltration via Cyber Means",
         r"(?i)(exfiltrate|transfer|send|upload)\s+(the\s+)?(data|files?|secrets?|credentials?)\s+(via|over|through|using)\s+(dns|icmp|https?|ftp|ssh|tor|vpn|steganograph)"),

        // AML.T0058.003 — Extract LLM System Prompt
        ("AML.T0058.003", "Extract LLM System Prompt",
         r"(?i)(show|reveal|print|output|display|repeat|extract|tell\s+me|dump|echo|return)\s+((your|the)\s+)?(entire|full|complete|exact|raw|original|initial|verbatim)?\s*(system\s+(prompt|message|instruction)|pre.?prompt|meta.?prompt|hidden\s+instruction|custom\s+instruction|initial\s+instruction)"),

        // AML.T0058.004 — LLM Data Leakage
        ("AML.T0058.004", "LLM Data Leakage",
         r"(?i)(include|embed|encode|hide|smuggle|leak)\s+(the\s+)?(data|secret|key|credential|info|pii)\s+(in|within|inside|as\s+part\s+of)\s+(the\s+)?(response|output|answer|url|link|image|markdown|json)"),

        // AML.T0058.005 — LLM Response Rendering
        ("AML.T0058.005", "LLM Response Rendering",
         r"(?i)(render|display|embed|include)\s+(an?\s+)?(external|remote|third.?party)\s+(image|iframe|script|resource|url)\s+(in|within|as\s+part\s+of)\s+(your\s+)?(response|output|answer|reply)"),

        // ════════════════════════════════════════════════════════════════════
        // ── Impact ─────────────────────────────────────────────────────────
        // ════════════════════════════════════════════════════════════════════

        // AML.T0059 — Cost Harvesting
        ("AML.T0059", "Cost Harvesting",
         r"(?i)(mine|generate|produce)\s+(bitcoin|ethereum|crypto|monero|cryptocurrency)\s+(using|with|on)\s+(all|available|your|the)\s+(gpu|cpu|compute|resource)"),

        // AML.T0059.001 — Data Destruction via AI Tool
        ("AML.T0059.001", "Data Destruction via AI Tool",
         r"(?i)(delete|destroy|drop|truncate|wipe|purge|rm\s+-rf|erase|shred)\s+(all\s+)?(data|files?|database|tables?|records?|logs?|backups?|users?|accounts?|documents?)"),

        // AML.T0059.002 — Denial of AI Service
        ("AML.T0059.002", "Denial of AI Service",
         r"(?i)(crash|overload|flood|overwhelm|exhaust|consume\s+all|deplete)\s+(the\s+)?(model|service|api|server|gpu|memory|tokens?|context|resources?|rate\s+limit)"),

        // AML.T0059.003 — Erode AI Model Integrity
        ("AML.T0059.003", "Erode AI Model Integrity",
         r"(?i)(corrupt|degrade|poison|manipulate|bias|skew|erode)\s+(the\s+)?(model|ai|output|behavior|response|prediction|training|weights?|integrity|accuracy|alignment)"),

        // AML.T0059.004 — Erode Dataset Integrity
        ("AML.T0059.004", "Erode Dataset Integrity",
         r"(?i)(corrupt|degrade|poison|manipulate|tamper)\s+(the\s+)?(dataset|training\s+data|fine.?tuning\s+data|evaluation\s+data|benchmark|test\s+set|validation\s+set)"),

        // AML.T0059.005 — Evade AI Model (Impact)
        // Behavioral: evasion at scale causing impact, not distinct from AML.T0051 content-wise.
        // Detection covered by AML.T0051 rules above.

        // AML.T0059.006 — External Harms
        ("AML.T0059.006", "External Harms",
         r"(?i)(how\s+to\s+(make|build|create|synthesize|manufacture)\s+(a\s+)?(bomb|weapon|explosive|poison|bioweapon|chemical\s+weapon|nerve\s+agent|ricin|sarin|anthrax)|instructions?\s+for\s+(making|building|creating|synthesizing)\s+(a\s+)?(weapon|explosive|drug|poison|bioweapon))"),

        // AML.T0059.007 — Machine Compromise
        ("AML.T0059.007", "Machine Compromise",
         r"(?i)(take\s+over|compromise|hack|exploit|backdoor|rootkit|own|pwn)\s+(this\s+)?(machine|server|host|system|computer|infrastructure|network)"),

        // AML.T0059.008 — Spamming AI System
        ("AML.T0059.008", "Spamming AI System",
         r"(?i)(flood|spam|fill|overwrite|pollute|overwhelm)\s+(the\s+)?(context|memory|history|conversation|rag|knowledge\s+base|index|queue)\s+(with\s+)?(garbage|noise|random|fake|junk|nonsense|chaff|irrelevant)"),
    ]
});

pub struct AtlasEngine {
    set: RegexSet,
    ids: Vec<&'static str>,
    names: Vec<&'static str>,
}

impl AtlasEngine {
    pub fn new() -> Self {
        let patterns: Vec<_> = RULES.iter().map(|(_, _, p)| *p).collect();
        let ids: Vec<_> = RULES.iter().map(|(id, _, _)| *id).collect();
        let names: Vec<_> = RULES.iter().map(|(_, name, _)| *name).collect();
        AtlasEngine {
            set: RegexSet::new(&patterns).expect("bad regex pattern"),
            ids,
            names,
        }
    }

    pub fn scan(&self, text: &str) -> Vec<String> {
        self.set
            .matches(text)
            .iter()
            .map(|i| self.ids[i].to_string())
            .collect()
    }

    #[allow(dead_code)]
    pub fn scan_with_names(&self, text: &str) -> Vec<(String, String)> {
        self.set
            .matches(text)
            .iter()
            .map(|i| (self.ids[i].to_string(), self.names[i].to_string()))
            .collect()
    }

    #[allow(dead_code)]
    pub fn rule_count(&self) -> usize {
        self.ids.len()
    }
}
