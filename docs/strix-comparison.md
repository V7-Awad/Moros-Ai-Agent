# مراجعة Moros AI ومقارنته بـ Strix

**تاريخ المراجعة:** 2026-11-22  
**مرجع Strix:** `usestrix/strix`، revision `a1ccf777d80e812edf23fc8b82bdc17def6143ac`  
**نطاق المراجعة:** ملفات المشروع الحالية في `D:\Moros Ai`، مع قراءة النسخة الحالية من المستودع المرجعي محليًا.

## الحكم المختصر

Moros AI يملك أساسًا جيدًا كـ **طبقة منهجية وواجهة تشغيل لمهام Web Pentest المصرّح بها**: لديه 14 skill، أدوات جمع وتحليل JavaScript، بنية target/output، Dashboard، وقواعد معلنة للموافقة البشرية. لكنه حاليًا ليس منافسًا وظيفيًا لمحرك Strix؛ لأن قلب التنفيذ في `hackbot_orchestrator.py` ما زال placeholder، ولا توجد بعد طبقة فعلية لاستدعاء LLM أو تشغيل agent أو حفظ جلسات قابلة للاستئناف.

أفضل قرار ليس نسخ Strix بالكامل. الأفضل هو تحويل Moros إلى مشروع أصغر وأكثر وضوحًا: **execution engine حقيقي، sandbox آمن، state machine قابلة للاستئناف، ثم توسيع التغطية**. بعد ذلك يمكن الاحتفاظ بالـ skills الحالية كميزة تخصصية، بدل الدخول في منافسة شاملة مع كل ما يقدمه Strix.

## ما يملكه Moros حاليًا

المشروع الحالي منظم حول pipeline ثابت:

`recon-subdomain → js-discover → js-analyze → content-discovery → vulnerability skills → report-conglomeration`

ويوجد فصل مفهوم بين:

- `skills/`: منهجيات متخصصة.
- `tools/`: أدوات Python لجمع وتحليل البيانات.
- `targets/<domain>/output/`: artifacts وlogs وfindings.
- `dashboard/`: واجهة محلية لمتابعة الحالة والنتائج.

هذه نقطة قوة مهمة؛ فالنتائج قابلة للقراءة من ملفات، والواجهة لا تعتمد على قاعدة بيانات معقدة. كما أن المشروع يضع authorization وhuman review في الوثائق وفي أسماء الملفات، وهذا يجعل النطاق الأخلاقي واضحًا. التفاصيل موجودة في [README المحلي](../README.md) و[وثيقة المعمارية](../docs/architecture.md).

## الفروق الأساسية عن Strix

### 1. التنفيذ الفعلي

في Moros، الدالة `_execute_skill()` تنشئ نتيجة بحالة `PENDING` ثم تغيّرها إلى `PLACEHOLDER` وتسجل أن التنفيذ كان سيحدث لاحقًا. كما أن `_run_review()` يخرج بعد أول محاولة ولا يقرأ نتيجة المراجعة فعليًا. هذا يعني أن تشغيل `python run.py --target ...` يبني سجلًا وخطة، لكنه لا يشغّل agent حقيقيًا ولا skill حقيقية.

في Strix، دورة التشغيل مبنية حول `Runner.run_streamed()`، جلسة لكل agent، coordinator لحالة الوكلاء، وlifecycle tools لإنهاء المهمة أو انتظار المستخدم أو انتظار الوكلاء. كما يحفظ Strix state في ملفات وSQLite ويستطيع استعادة scan متوقفًا. راجع [orchestrator المحلي](../tools/hackbot_orchestrator.py)، و[Strix execution loop](.work/strix-reference/strix/core/execution.py)، و[Strix runner](.work/strix-reference/strix/core/runner.py).

### 2. نموذج الوكلاء

Moros يملك pipeline خطيًا ثابتًا ويشغّل كل skill بالترتيب. dependencies فيه تحذيرية فقط: إذا لم تُشغّل skill سابقة، يظهر warning ولا يتوقف التنفيذ. أما Strix فيملك agent graph: root agent ينشئ child agents بمهام محددة، وكل agent له status وparent وmailbox وsession. هذا يسمح بالتوازي، انتظار agent آخر، واستئناف الوكلاء.

### 3. الأدوات والبيئة التنفيذية

أدوات Moros الحالية wrappers محلية حول Playwright وHTTP وتحليل الملفات. هذا مناسب كبداية، لكنه لا يوفر sandbox موحدًا لتنفيذ أوامر وأدوات فحص معزولة. Strix يشغّل runtime داخل sandbox، ويعرض أدوات للـ shell وbrowser وproxy وMCP وcoverage وnotes وtodo وthreat model وreporting. هذه الطبقة هي السبب في أن Strix يستطيع تنفيذ PoC والتحقق منه بدل الاكتفاء بإشارة أولية.

### 4. إدارة السياق والميزانية والأخطاء

Moros يسجل `model` كاسم نصي، لكنه لا يملك adapter فعليًا لمزود LLM ولا token budget ولا retry policy ولا compaction للسياق. Strix يضم إعدادات للموديل، التكاليف، حد الإنفاق، retries للأخطاء العابرة، compaction، دعم الصور، streaming، وحالات pause/resume. هذه قدرات تشغيلية أهم من زيادة عدد الـ skills في المرحلة الحالية.

### 5. التغطية

Moros يركز على reconnaissance وJavaScript وXSS وSSRF وبعض auth/IdP. Strix يعلن تغطية أوسع تشمل access control/IDOR، SQL/NoSQL injection، command injection، SSTI، XXE، deserialization، CSRF، business logic، JWT، API security، cloud/infrastructure، وغيرها. كما أن كتالوج skills لديه ديناميكي وقابل للإضافة من مجلدات خارجية. راجع [Strix skills documentation](https://github.com/usestrix/strix/blob/main/docs/advanced/skills.mdx) و[Strix README](https://github.com/usestrix/strix/blob/main/README.md).

### 6. تجربة الاستخدام والتكامل

Moros لديه Dashboard محلي جيد من ناحية العرض: targets، findings، endpoints، logs، checkpoints، وتقارير Markdown. لكن التشغيل والحالة في الذاكرة فقط، ولا توجد قاعدة حالة دائمة للـ scans أو resume بعد إغلاق العملية. Strix لديه CLI تفاعلي وnon-interactive، viewer للـ runs، scan modes، target lists، diff scope، وCI/CD exit codes. كما يضع نتائج التشغيل داخل run directory منظم.

### 7. الاختبارات وجودة المنتج

في النسخة التي تمت مراجعتها، Moros لديه ملفات مشروع صغيرة نسبيًا: نحو 12 ملف Python و2,779 سطرًا خارج `.work`، بينما نسخة Strix المرجعية تحتوي نحو 137 ملف Python و39,440 سطرًا Python، إضافة إلى واجهة Go واختبارات واسعة. الرقم ليس مقياس جودة بحد ذاته، لكنه يوضح أن Strix في مرحلة productization متقدمة، بينما Moros ما زال في مرحلة prototype/architecture.

## نتائج فنية تستحق الإصلاح قريبًا

1. **إصلاح أمر التحقق على Windows.** `python run.py --check` يفشل قبل فحص المتطلبات لأن الـ banner يحتوي Unicode ولا يناسب console بترميز CP1252. `compileall` يمر بنجاح، لكن مسار التشغيل الأساسي ليس cross-platform بعد. يجب إما طباعة banner ASCII، أو ضبط UTF-8 بأمان، أو استخدام `sys.stdout.reconfigure(errors="replace")`.

2. **منع الادعاء بأن HITL مُفعّل قبل ربطه بالمحرك.** في orchestrator، checkpoint يسجل رسالة `Awaiting human approval` لكنه لا ينتظر قرارًا ولا يمنع `_execute_skill()` من الاستمرار. يجب أن يتحول checkpoint إلى state blocking حقيقي: `PENDING_APPROVAL → APPROVED/REJECTED`, مع timeout وسجل قرار.

3. **جعل dependency validation مانعًا فعليًا.** حاليًا dependency غير الموجودة تنتج warning فقط. يجب بناء DAG والتحقق منه قبل التشغيل، أو السماح صراحةً بتشغيل skill على artifacts سابقة بعد validation لوجودها وصحتها.

4. **تقوية Dashboard قبل أي exposure خارج localhost.** الخادم يرسل `Access-Control-Allow-Origin: *`، ولا توجد authentication، ويشغل subprocess من HTTP endpoint. هذا مقبول كتجربة محلية مغلقة فقط، وليس كخدمة على شبكة. يجب إضافة token محلي، تعطيل CORS المفتوح، التحقق الصارم من أسماء targets، ورفض `--host 0.0.0.0` افتراضيًا.

5. **إلغاء الاعتماد على `hash()` لإنشاء checkpoint IDs.** قيمة Python hash غير ثابتة بين العمليات، لذلك قد يتغير ID لنفس endpoint بعد إعادة التشغيل. استخدم SHA-256 مختصرًا من method + normalized URL + parameter.

6. **فصل الحالة الدائمة عن `active_scans`.** dictionary في الذاكرة يضيع عند restart ولا يتعامل جيدًا مع أكثر من process. استخدم SQLite صغيرًا أو ملفات JSON ذرية لكل run، مع `run_id`, status, timestamps, PID/process handle، وresume metadata.

7. **إضافة اختبارات حقيقية للمحرك والـ API.** توجد ترجمة Python ناجحة، لكن لا يوجد test suite واضح للمشروع المحلي. الحد الأدنى: اختبارات dependency ordering، scope enforcement، checkpoint transitions، target path validation، parser robustness، dashboard API، وdry-run.

## ما أقترح عمله بعد ذلك

### المرحلة الأولى: تحويل Moros من prototype إلى محرك يعمل

الهدف هو تنفيذ skill واحدة end-to-end فقط، مثل `js-discover`، بدل محاولة تشغيل الـ 14 دفعة واحدة.

- تعريف interface موحد: `SkillContext`, `SkillInput`, `SkillResult`, `Artifact`, `Finding`.
- اختيار backend واحد أولًا، مع adapter مستقل للـ LLM.
- تشغيل كل skill في subprocess أو worker مع timeout وexit status.
- حفظ event log بصيغة JSONL، وmanifest يصف artifacts.
- جعل review skill تقرأ artifacts وتصدر `PASS/FAIL/BLOCKED` فعلية.
- جعل retry يعيد skill فقط عند فشل قابل للإصلاح.

### المرحلة الثانية: بناء state machine وHITL حقيقي

أضف run states واضحة: `created`, `authorized`, `running`, `waiting_approval`, `paused`, `failed`, `completed`, `cancelled`. كل انتقال يجب أن يكتب event غير قابل للتعديل. الـ Dashboard يقرأ هذه الحالة ويستدعي endpoint قرارًا لا يكفي أن يكتب JSON؛ بل يجب أن يوقظ worker المنتظر أو يرفض الانتقال إذا كان checkpoint غير صالح.

### المرحلة الثالثة: sandbox وموارد التشغيل

قبل إضافة exploit skills جديدة، أضف sandbox قابلًا للتحكم في الشبكة والملفات والوقت. حدّد allowlist للـ domains، rate limits، maximum request count، execution timeout، وkill كامل لسلسلة subprocess عند الإيقاف. هذا يحقق جزءًا من القيمة التي يقدمها Strix دون نسخ كل runtime الخاص به.

### المرحلة الرابعة: توسيع التغطية بذكاء

بعد استقرار المحرك، الأولوية المنطقية ليست إضافة XSS أخرى، لأن Moros يغطي XSS جيدًا نسبيًا. أضف بالترتيب:

1. API/OpenAPI/Postman input.
2. IDOR وbroken access control.
3. authentication/session/JWT.
4. SQLi وcommand injection وSSTI عبر adapters آمنة.
5. business logic وrace conditions.
6. SAST/diff-aware testing للكود المحلي.

### المرحلة الخامسة: CI/CD وقياس الجودة

أضف `--non-interactive`, `--scan-mode quick|standard|deep`, و`--fail-on`. اجعل exit code يميز بين execution error وfinding فوق threshold، كما يفعل Strix في تكامل CI/CD. أضف fixtures وregression corpus، وقياسات مثل: نسبة findings التي لها evidence، false-positive rate، زمن skill، تكلفة LLM، ونسبة artifacts المكتملة.

## القرار المقترح

لا أنصح حاليًا بمحاولة إعادة بناء Strix كاملًا داخل Moros. أنصح بتثبيت هوية Moros كـ **specialized, auditable, local-first assessment harness**:

- Strix يكون مرجعًا لأفكار runtime، sessions، agent graph، budgets، sandbox، viewer، وCI.
- Moros يحتفظ بميزة skills المتخصصة في JS/attack-surface workflows، وبـ authorization/HITL الصريح.
- أول milestone عملي: تشغيل `js-discover → js-analyze → report` فعليًا مع session واحدة، artifacts صحيحة، review blocking، وDashboard يعرض الحالة الحقيقية.

إذا نجح هذا المسار، يمكن بعده إضافة child agents أو parallel execution. أما قبل ذلك، فإضافة skills جديدة ستزيد حجم الخطة أكثر مما تزيد قدرة المنتج الفعلية.

## مراجع

[1]: https://github.com/usestrix/strix "Strix repository README and source"
[2]: https://github.com/usestrix/strix/blob/main/docs/advanced/skills.mdx "Strix skills documentation"
[3]: https://github.com/usestrix/strix/blob/main/docs/advanced/configuration.mdx "Strix configuration documentation"
[4]: https://github.com/usestrix/strix/blob/main/docs/integrations/ci-cd.mdx "Strix CI/CD integration documentation"
[5]: https://github.com/usestrix/strix/blob/main/docs/usage/scan-modes.mdx "Strix scan modes documentation"
