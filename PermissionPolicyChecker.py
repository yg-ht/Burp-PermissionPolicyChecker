from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IScannerCheck
from burp import IScanIssue

from javax.swing import GroupLayout
from javax.swing import JPanel
from javax.swing import JCheckBox
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JScrollPane
from javax.swing import JTextArea

import re


class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck):
    """
    Burp Suite legacy Python/Jython extension for passively identifying
    Permissions-Policy weaknesses, errors, and risky allowances.

    Structural reference: the supplied SourceMapper extension.
    Runtime target: Burp Extender with Jython 2.7.
    """

    KNOWN_DIRECTIVES = set([
        'accelerometer',
        'ambient-light-sensor',
        'aria-notify',
        'attribution-reporting',
        'autoplay',
        'bluetooth',
        'browsing-topics',
        'camera',
        'captured-surface-control',
        'ch-ua-high-entropy-values',
        'compute-pressure',
        'cross-origin-isolated',
        'deferred-fetch',
        'deferred-fetch-minimal',
        'display-capture',
        'encrypted-media',
        'fullscreen',
        'gamepad',
        'geolocation',
        'gyroscope',
        'hid',
        'identity-credentials-get',
        'idle-detection',
        'language-detector',
        'local-fonts',
        'magnetometer',
        'microphone',
        'midi',
        'on-device-speech-recognition',
        'otp-credentials',
        'payment',
        'picture-in-picture',
        'private-state-token-issuance',
        'private-state-token-redemption',
        'publickey-credentials-create',
        'publickey-credentials-get',
        'screen-wake-lock',
        'serial',
        'speaker-selection',
        'storage-access',
        'summarizer',
        'translator',
        'usb',
        'web-share',
        'window-management',
        'xr-spatial-tracking'
    ])

    # Features that are normally sensitive because they expose devices,
    # location, identity flows, payment, local environment, or stronger tracking signals.
    HIGH_RISK_DIRECTIVES = set([
        'bluetooth',
        'camera',
        'display-capture',
        'geolocation',
        'hid',
        'identity-credentials-get',
        'idle-detection',
        'local-fonts',
        'microphone',
        'midi',
        'otp-credentials',
        'payment',
        'publickey-credentials-create',
        'publickey-credentials-get',
        'screen-wake-lock',
        'serial',
        'speaker-selection',
        'storage-access',
        'usb',
        'window-management',
        'xr-spatial-tracking'
    ])

    # Features which are often not catastrophic alone, but are still worth surfacing when broad.
    MEDIUM_RISK_DIRECTIVES = set([
        'accelerometer',
        'ambient-light-sensor',
        'attribution-reporting',
        'autoplay',
        'browsing-topics',
        'captured-surface-control',
        'ch-ua-high-entropy-values',
        'compute-pressure',
        'encrypted-media',
        'fullscreen',
        'gamepad',
        'gyroscope',
        'magnetometer',
        'picture-in-picture',
        'private-state-token-issuance',
        'private-state-token-redemption',
        'web-share'
    ])

    DEFAULT_DENY_DIRECTIVES = [
        'accelerometer',
        'ambient-light-sensor',
        'attribution-reporting',
        'bluetooth',
        'browsing-topics',
        'camera',
        'ch-ua-high-entropy-values',
        'display-capture',
        'geolocation',
        'gyroscope',
        'hid',
        'idle-detection',
        'local-fonts',
        'magnetometer',
        'microphone',
        'midi',
        'otp-credentials',
        'payment',
        'screen-wake-lock',
        'serial',
        'speaker-selection',
        'storage-access',
        'usb',
        'window-management',
        'xr-spatial-tracking'
    ]

    def debug(self, message, lvl=1):
        try:
            debug_level = int(self.debugLevel.getText())
        except Exception:
            debug_level = 1

        if debug_level >= lvl:
            try:
                print(message)
            except UnicodeEncodeError:
                print(message.encode('utf-8'))
        return

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.issueDict = {}

        self.onlyInScope = self.defineCheckBox('Only in scope resources', True)
        self.onlyInScope.setToolTipText('Only analyse resources that Burp considers in scope')

        self.onlyHtml = self.defineCheckBox('Only analyse document-like HTML responses', True)
        self.onlyHtml.setToolTipText('Reduces noise by avoiding static resources and API responses')

        self.flagMissingPolicy = self.defineCheckBox('Flag missing Permissions-Policy header', True)
        self.flagMissingPolicy.setToolTipText('Useful for hardening reviews. This is usually informational or low severity, not a direct vulnerability.')

        self.flagDeprecatedFeaturePolicy = self.defineCheckBox('Flag deprecated Feature-Policy header', True)
        self.flagDeprecatedFeaturePolicy.setToolTipText('Feature-Policy is the predecessor of Permissions-Policy')

        self.flagReportOnlyOnly = self.defineCheckBox('Flag report-only policy without enforcing policy', True)
        self.flagReportOnlyOnly.setToolTipText('Report-only policies do not enforce restrictions')

        self.flagSyntaxErrors = self.defineCheckBox('Flag syntax errors and malformed directives', True)
        self.flagSyntaxErrors.setToolTipText('Detects legacy syntax, missing equals signs, invalid allowlists, and suspicious semicolon use')

        self.flagUnknownDirective = self.defineCheckBox('Flag unknown directives', True)
        self.flagUnknownDirective.setToolTipText('Detects typos and unsupported directive names based on the embedded directive list')

        self.flagDuplicateDirectives = self.defineCheckBox('Flag duplicate directives', True)
        self.flagDuplicateDirectives.setToolTipText('Duplicate directives can create ambiguity or hide policy mistakes')

        self.flagWildcard = self.defineCheckBox('Flag wildcard allowances for sensitive features', True)
        self.flagWildcard.setToolTipText('Flags high-risk or medium-risk directives set to *')

        self.flagCrossOrigin = self.defineCheckBox('Flag cross-origin allowances for high-risk features', True)
        self.flagCrossOrigin.setToolTipText('Flags high-risk directives that allow explicit third-party origins')

        self.flagSensitiveNotDenied = self.defineCheckBox('Flag sensitive features not explicitly denied', True)
        self.flagSensitiveNotDenied.setToolTipText('Compares the policy with the configured deny-by-default directive list')

        self.flagIframeAllow = self.defineCheckBox('Flag risky iframe allow attributes', True)
        self.flagIframeAllow.setToolTipText('Looks for cross-origin iframes that allow high-risk features')

        self.debugLevel = JTextField(str(1), 1)
        self.debugLevelLabel = JLabel('Debug level (0-3)')
        self.debugLevel.setToolTipText('0 is silent, 3 is verbose')
        self.debugLevelGroup = JPanel()
        self.debugLevelGroup.add(self.debugLevelLabel)
        self.debugLevelGroup.add(self.debugLevel)

        self.denyDirectiveList = JTextField(','.join(self.DEFAULT_DENY_DIRECTIVES), 90)
        self.denyDirectiveListLabel = JLabel('Directives expected to be explicitly denied with ()')
        self.denyDirectiveList.setToolTipText('Comma-separated list. These are checked when the sensitive-feature baseline option is enabled.')
        self.denyDirectiveListGroup = JPanel()
        self.denyDirectiveListGroup.add(self.denyDirectiveListLabel)
        self.denyDirectiveListGroup.add(self.denyDirectiveList)

        self.notes = JTextArea(
            'This extension is intentionally conservative. It separates missing hardening from likely misconfiguration and dangerous allowance.\n'
            'Tune the expected deny-list for applications that legitimately require passkeys, payments, video, geolocation, or screen sharing.'
        )
        self.notes.setEditable(False)
        self.notes.setLineWrap(True)
        self.notes.setWrapStyleWord(True)
        self.notesScroll = JScrollPane(self.notes)

        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.onlyHtml, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagMissingPolicy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagDeprecatedFeaturePolicy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagReportOnlyOnly, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagSyntaxErrors, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagUnknownDirective, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagDuplicateDirectives, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagWildcard, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagCrossOrigin, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagSensitiveNotDenied, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.flagIframeAllow, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.denyDirectiveListGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.notesScroll, GroupLayout.PREFERRED_SIZE, 900, GroupLayout.PREFERRED_SIZE)
            )
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.onlyHtml, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagMissingPolicy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagDeprecatedFeaturePolicy, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagReportOnlyOnly, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagSyntaxErrors, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagUnknownDirective, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagDuplicateDirectives, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagWildcard, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagCrossOrigin, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagSensitiveNotDenied, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.flagIframeAllow, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.denyDirectiveListGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.notesScroll, GroupLayout.PREFERRED_SIZE, 80, GroupLayout.PREFERRED_SIZE)
        )

        callbacks.setExtensionName('Permissions Policy Auditor')
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)

        self.debug('Permissions Policy Auditor loaded', 1)
        return

    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox

    def getTabCaption(self):
        return 'Permissions Policy Auditor'

    def getUiComponent(self):
        return self.tab

    def processHttpMessage(self, toolFlag, messageIsRequest, message):
        if messageIsRequest:
            return

        try:
            issues = self.analyseMessage(message)
            if issues:
                httpService = message.getHttpService()
                request = self._helpers.analyzeRequest(httpService, message.getRequest())
                reqURL = request.getUrl()
                self.issueDict[str(reqURL)] = issues
                self.debug('Stored Permissions-Policy findings for: ' + str(reqURL), 2)
        except Exception as e:
            self.debug('Listener analysis failed: ' + str(e), 0)

        return

    def doPassiveScan(self, baseRequestResponse):
        httpService = baseRequestResponse.getHttpService()
        request = self._helpers.analyzeRequest(httpService, baseRequestResponse.getRequest())
        reqURL = request.getUrl()

        try:
            issue_records = self.analyseMessage(baseRequestResponse)
        except Exception as e:
            self.debug('Passive analysis failed: ' + str(e), 0)
            issue_records = []

        if not issue_records and str(reqURL) in self.issueDict:
            issue_records = self.issueDict[str(reqURL)]

        if not issue_records:
            self.debug('No Permissions-Policy issues for: ' + str(reqURL), 3)
            return None

        burp_issues = []
        for record in issue_records:
            burp_issues.append(issue(
                httpService,
                reqURL,
                [baseRequestResponse],
                record['name'],
                record['detail'],
                record['severity'],
                record['confidence'],
                record['background'],
                record['remediation'],
                None
            ))

        return burp_issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and str(existingIssue.getUrl()) == str(newIssue.getUrl()):
            self.debug('Duplicate Permissions-Policy issue suppressed: ' + existingIssue.getIssueName(), 2)
            return -1
        return 0

    def extensionUnloaded(self):
        self.debug('Permissions Policy Auditor unloaded', 1)
        return

    def analyseMessage(self, message):
        issues = []

        if message is None or message.getResponse() is None:
            return issues

        httpService = message.getHttpService()
        requestInfo = self._helpers.analyzeRequest(httpService, message.getRequest())
        reqURL = requestInfo.getUrl()

        if self.onlyInScope.isSelected() and not self._callbacks.isInScope(reqURL):
            self.debug('Out of scope, skipping: ' + str(reqURL), 3)
            return issues

        response = message.getResponse()
        responseInfo = self._helpers.analyzeResponse(response)
        headers = list(responseInfo.getHeaders())
        status = self.getStatusCode(headers, responseInfo)

        if status not in [200, 201, 202, 203, 204, 205, 206, 304]:
            self.debug('Skipping status ' + str(status) + ' for: ' + str(reqURL), 3)
            return issues

        if self.onlyHtml.isSelected() and not self.isHtmlDocument(reqURL, headers):
            self.debug('Not a document-like HTML response, skipping: ' + str(reqURL), 3)
            return issues

        body = ''
        try:
            bodyBytes = response[responseInfo.getBodyOffset():]
            body = self._helpers.bytesToString(bodyBytes)
        except Exception:
            body = ''

        permissions_headers = self.getHeaderValues(headers, 'Permissions-Policy')
        report_only_headers = self.getHeaderValues(headers, 'Permissions-Policy-Report-Only')
        feature_policy_headers = self.getHeaderValues(headers, 'Feature-Policy')
        reporting_endpoints_headers = self.getHeaderValues(headers, 'Reporting-Endpoints')

        if self.flagMissingPolicy.isSelected() and len(permissions_headers) == 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy header missing',
                'The response does not include an enforcing <code>Permissions-Policy</code> header.',
                'Information',
                'Certain',
                'Permissions-Policy can restrict access to browser features such as camera, microphone, geolocation, payment, USB, serial, and screen capture. Missing policy is usually a hardening gap rather than a direct vulnerability.',
                'Add a least-privilege Permissions-Policy header for document responses. For applications that do not need privileged browser APIs, explicitly deny sensitive features with an empty allowlist, for example <code>camera=(), microphone=(), geolocation=()</code>.'
            ))

        if self.flagDeprecatedFeaturePolicy.isSelected() and len(feature_policy_headers) > 0:
            issues.append(self.makeIssueRecord(
                'Deprecated Feature-Policy header present',
                'The response includes the deprecated <code>Feature-Policy</code> header: <pre>' + self.htmlEscape('\n'.join(feature_policy_headers)) + '</pre>',
                'Low',
                'Certain',
                'Feature-Policy was the predecessor to Permissions-Policy. Modern policy configuration should use the Permissions-Policy header syntax.',
                'Replace Feature-Policy with Permissions-Policy. Check syntax carefully, because legacy values such as <code>\'none\'</code> and semicolon-separated directives are not equivalent to modern header syntax.'
            ))

        if self.flagReportOnlyOnly.isSelected() and len(report_only_headers) > 0 and len(permissions_headers) == 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy configured in report-only mode only',
                'The response includes <code>Permissions-Policy-Report-Only</code> but does not include an enforcing <code>Permissions-Policy</code> header.',
                'Information',
                'Certain',
                'Report-only mode can collect telemetry, but it does not block feature use.',
                'Keep the report-only header for staged rollout if useful, but add an enforcing Permissions-Policy header once legitimate feature use has been confirmed.'
            ))

        if len(permissions_headers) > 0:
            parsed = self.parsePolicyHeaders(permissions_headers, 'Permissions-Policy')
            issues.extend(self.evaluateParsedPolicy(parsed, reporting_endpoints_headers, False))

        if len(report_only_headers) > 0:
            parsed_ro = self.parsePolicyHeaders(report_only_headers, 'Permissions-Policy-Report-Only')
            issues.extend(self.evaluateParsedPolicy(parsed_ro, reporting_endpoints_headers, True))

        if self.flagSensitiveNotDenied.isSelected() and len(permissions_headers) > 0:
            parsed_for_baseline = self.parsePolicyHeaders(permissions_headers, 'Permissions-Policy')
            baseline_issue = self.evaluateStrictBaseline(parsed_for_baseline)
            if baseline_issue is not None:
                issues.append(baseline_issue)

        if self.flagIframeAllow.isSelected() and body:
            iframe_issues = self.evaluateIframeAllowAttributes(reqURL, body, permissions_headers)
            issues.extend(iframe_issues)

        return self.deduplicateIssueRecords(issues)

    def parsePolicyHeaders(self, header_values, header_name):
        result = {
            'header_name': header_name,
            'directives': [],
            'errors': [],
            'raw': header_values
        }

        for header_value in header_values:
            if header_value is None or str(header_value).strip() == '':
                result['errors'].append('Empty ' + header_name + ' header value')
                continue

            parts = self.splitOutsideQuotesAndParens(str(header_value), ',')
            for part in parts:
                raw_part = part.strip()
                if raw_part == '':
                    result['errors'].append('Empty directive in ' + header_name + ' header')
                    continue

                segments = self.splitOutsideQuotesAndParens(raw_part, ';')
                directive_segment = segments[0].strip()
                params = []
                if len(segments) > 1:
                    for segment in segments[1:]:
                        segment = segment.strip()
                        if segment:
                            params.append(segment)

                if '=' not in directive_segment:
                    if "'none'" in directive_segment or "'self'" in directive_segment or ';' in raw_part:
                        result['errors'].append('Possible legacy Feature-Policy syntax inside ' + header_name + ': ' + raw_part)
                    else:
                        result['errors'].append('Malformed directive without equals sign: ' + raw_part)
                    continue

                name, allowlist = directive_segment.split('=', 1)
                name = name.strip().lower()
                allowlist = allowlist.strip()

                if not re.match(r'^[a-z0-9-]+$', name):
                    result['errors'].append('Invalid directive name: ' + self.htmlEscape(name))
                    continue

                allowlist_info = self.parseAllowlist(allowlist)

                for param in params:
                    if not re.match(r'^report-to\s*=\s*[A-Za-z0-9_.-]+$', param):
                        result['errors'].append('Unknown or malformed directive parameter on ' + name + ': ' + param)

                result['directives'].append({
                    'name': name,
                    'allowlist': allowlist,
                    'allowlist_info': allowlist_info,
                    'params': params,
                    'raw': raw_part
                })

        return result

    def parseAllowlist(self, allowlist):
        info = {
            'raw': allowlist,
            'valid': True,
            'empty': False,
            'wildcard': False,
            'tokens': [],
            'self': False,
            'src': False,
            'origins': [],
            'errors': []
        }

        value = allowlist.strip()

        if value == '*':
            info['wildcard'] = True
            return info

        if value == '()':
            info['empty'] = True
            return info

        if value in ['none', "'none'", 'self', "'self'", 'src', "'src'"]:
            info['valid'] = False
            info['errors'].append('Allowlist value appears to use legacy or iframe-style syntax outside parentheses: ' + value)
            return info

        if not (value.startswith('(') and value.endswith(')')):
            info['valid'] = False
            info['errors'].append('Allowlist should be *, (), or a parenthesised list such as (self "https://example.com")')
            return info

        inner = value[1:-1].strip()
        if inner == '':
            info['empty'] = True
            return info

        tokens = self.tokenizeAllowlist(inner)
        info['tokens'] = tokens

        for token in tokens:
            normalised = token.strip().strip('"').strip("'")
            lower = normalised.lower()

            if lower == '*':
                info['valid'] = False
                info['errors'].append('Wildcard must be used alone as * and not inside a parenthesised allowlist')
            elif lower == 'self':
                info['self'] = True
            elif lower == 'src':
                info['src'] = True
            elif re.match(r'^https?://', lower):
                info['origins'].append(normalised)
            else:
                info['valid'] = False
                info['errors'].append('Unrecognised allowlist token: ' + token)

        return info

    def evaluateParsedPolicy(self, parsed, reporting_endpoints_headers, report_only):
        issues = []
        header_label = parsed['header_name']
        disposition = 'report-only' if report_only else 'enforcing'

        if self.flagSyntaxErrors.isSelected() and len(parsed['errors']) > 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy syntax error',
                'One or more syntax errors were identified in the ' + self.htmlEscape(header_label) + ' header:<pre>' + self.htmlEscape('\n'.join(parsed['errors'])) + '</pre>',
                'Low',
                'Certain',
                'Malformed Permissions-Policy directives may be ignored or interpreted differently than intended. This can silently remove expected browser feature restrictions.',
                'Use modern Permissions-Policy syntax: comma-separated header directives, each in the form <code>feature=allowlist</code>. Use <code>()</code> to deny a feature, <code>*</code> to allow all origins, or <code>(self "https://example.com")</code> for a restricted allowlist.'
            ))

        seen = {}
        duplicates = []
        unknown = []
        invalid_allowlists = []
        wildcard_findings = []
        cross_origin_findings = []
        missing_reporting_endpoint = []

        for directive in parsed['directives']:
            name = directive['name']
            allowlist = directive['allowlist']
            allowlist_info = directive['allowlist_info']

            if name in seen:
                duplicates.append(name)
            seen[name] = True

            if name not in self.KNOWN_DIRECTIVES:
                unknown.append(name)

            if not allowlist_info['valid']:
                invalid_allowlists.append(name + '=' + allowlist + ' -> ' + '; '.join(allowlist_info['errors']))

            if allowlist_info['wildcard']:
                if name in self.HIGH_RISK_DIRECTIVES:
                    wildcard_findings.append(name + '=*')
                elif name in self.MEDIUM_RISK_DIRECTIVES:
                    wildcard_findings.append(name + '=*')

            if name in self.HIGH_RISK_DIRECTIVES and len(allowlist_info['origins']) > 0:
                cross_origin_findings.append(name + '=' + allowlist)

            for param in directive['params']:
                if param.lower().startswith('report-to=') and len(reporting_endpoints_headers) == 0:
                    missing_reporting_endpoint.append(name + ' uses ' + param)

        if self.flagDuplicateDirectives.isSelected() and len(duplicates) > 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy duplicate directive',
                'The ' + self.htmlEscape(header_label) + ' header contains duplicate directives:<pre>' + self.htmlEscape('\n'.join(sorted(set(duplicates)))) + '</pre>',
                'Low',
                'Certain',
                'Duplicate directives make policy review harder and may lead to browser-specific behaviour or mistaken assumptions about which value applies.',
                'Declare each directive once. Merge repeated policy entries into a single explicit allowlist per feature.'
            ))

        if self.flagUnknownDirective.isSelected() and len(unknown) > 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy unknown directive',
                'The ' + self.htmlEscape(header_label) + ' header contains directive names not recognised by this extension:<pre>' + self.htmlEscape('\n'.join(sorted(set(unknown)))) + '</pre>',
                'Information',
                'Firm',
                'Unknown directive names are often typos. Browsers generally ignore unsupported or unknown policy-controlled features.',
                'Check each directive name against the current browser and specification documentation. If the directive is intentionally experimental, document the expected browser support.'
            ))

        if self.flagSyntaxErrors.isSelected() and len(invalid_allowlists) > 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy invalid allowlist',
                'The ' + self.htmlEscape(header_label) + ' header contains invalid or suspicious allowlists:<pre>' + self.htmlEscape('\n'.join(invalid_allowlists)) + '</pre>',
                'Low',
                'Certain',
                'An invalid allowlist can cause the intended restriction to fail, especially when legacy Feature-Policy syntax has been copied into a Permissions-Policy header.',
                'Use <code>()</code> for deny, <code>*</code> for all origins, or a parenthesised allowlist containing <code>self</code> and explicit origins.'
            ))

        if self.flagWildcard.isSelected() and len(wildcard_findings) > 0:
            severity = 'Medium'
            if report_only:
                severity = 'Information'
            issues.append(self.makeIssueRecord(
                'Permissions-Policy wildcard allowance for sensitive feature',
                'The ' + disposition + ' ' + self.htmlEscape(header_label) + ' header allows sensitive browser features for all origins:<pre>' + self.htmlEscape('\n'.join(wildcard_findings)) + '</pre>',
                severity,
                'Certain',
                'A wildcard allowlist grants the named feature to the top-level document and nested browsing contexts regardless of origin. This is high risk for device, location, identity, payment, and local-environment APIs.',
                'Replace <code>*</code> with <code>()</code> where the feature is unnecessary. If the feature is required, restrict it to <code>self</code> or explicit trusted origins, and ensure matching iframe <code>allow</code> attributes exist only where needed.'
            ))

        if self.flagCrossOrigin.isSelected() and len(cross_origin_findings) > 0:
            severity = 'Low'
            if report_only:
                severity = 'Information'
            issues.append(self.makeIssueRecord(
                'Permissions-Policy cross-origin allowance for high-risk feature',
                'The ' + disposition + ' ' + self.htmlEscape(header_label) + ' header allows high-risk browser features for explicit cross-origin entries:<pre>' + self.htmlEscape('\n'.join(cross_origin_findings)) + '</pre>',
                severity,
                'Firm',
                'Cross-origin feature delegation may be valid, but it expands the trust boundary to embedded or third-party content. A compromised third-party origin can become a path to feature abuse.',
                'Verify each third-party origin is necessary and trusted. Prefer <code>()</code> for unused features, <code>(self)</code> for first-party-only use, and tightly scoped explicit origins only for required integrations.'
            ))

        if len(missing_reporting_endpoint) > 0:
            issues.append(self.makeIssueRecord(
                'Permissions-Policy report-to endpoint missing',
                'One or more directives specify <code>report-to</code>, but the response does not include a <code>Reporting-Endpoints</code> header:<pre>' + self.htmlEscape('\n'.join(missing_reporting_endpoint)) + '</pre>',
                'Information',
                'Firm',
                'Permissions-Policy violation reporting requires a named reporting endpoint. Without endpoint configuration, expected server-side violation reports may not be delivered.',
                'Add a Reporting-Endpoints header defining the endpoint name used by the policy, or remove the report-to parameter if reporting is not required.'
            ))

        return issues

    def evaluateStrictBaseline(self, parsed):
        expected = self.getConfiguredDenyDirectives()
        if len(expected) == 0:
            return None

        directive_map = {}
        for directive in parsed['directives']:
            directive_map[directive['name']] = directive

        missing = []
        not_denied = []

        for name in expected:
            if name not in directive_map:
                missing.append(name)
            else:
                info = directive_map[name]['allowlist_info']
                if not info['empty']:
                    not_denied.append(name + '=' + directive_map[name]['allowlist'])

        if len(missing) == 0 and len(not_denied) == 0:
            return None

        detail_lines = []
        if len(missing) > 0:
            detail_lines.append('Missing expected deny directives:')
            detail_lines.extend(['  ' + x for x in sorted(missing)])
        if len(not_denied) > 0:
            detail_lines.append('Configured sensitive directives not fully denied:')
            detail_lines.extend(['  ' + x for x in sorted(not_denied)])

        return self.makeIssueRecord(
            'Permissions-Policy sensitive features not denied',
            'The enforcing Permissions-Policy header does not match the configured deny-by-default baseline:<pre>' + self.htmlEscape('\n'.join(detail_lines)) + '</pre>',
            'Low',
            'Firm',
            'A least-privilege Permissions-Policy should explicitly disable browser features that the application does not need. Omitted directives fall back to browser-defined defaults, which may be broader than the intended application policy.',
            'Tune the extension baseline for the application, then set unused sensitive features to <code>()</code>. Do not blindly deny features required for legitimate functionality such as passkeys, screen sharing, payments, or media capture.'
        )

    def evaluateIframeAllowAttributes(self, reqURL, body, permissions_headers):
        issues = []
        findings = []
        parent_policy_summary = 'No enforcing Permissions-Policy header was present on the parent response.'
        if len(permissions_headers) > 0:
            parent_policy_summary = 'An enforcing Permissions-Policy header was present. Browser behaviour depends on the intersection of the parent header and the iframe allow attribute.'

        iframe_tags = re.findall(r'<iframe\b[^>]*>', body, flags=re.IGNORECASE | re.DOTALL)
        if len(iframe_tags) == 0:
            return issues

        parent_origin = self.getOriginFromUrl(reqURL)

        for tag in iframe_tags:
            allow_value = self.getHtmlAttribute(tag, 'allow')
            if allow_value is None or allow_value.strip() == '':
                continue

            allowed_features = self.parseIframeAllowFeatures(allow_value)
            risky_features = []
            for feature in allowed_features:
                if feature in self.HIGH_RISK_DIRECTIVES:
                    risky_features.append(feature)

            if len(risky_features) == 0:
                continue

            src_value = self.getHtmlAttribute(tag, 'src')
            child_origin = self.getOriginFromSrc(parent_origin, src_value)
            cross_origin = False
            if child_origin is not None and parent_origin is not None and child_origin != parent_origin:
                cross_origin = True

            if cross_origin:
                findings.append('src=' + str(src_value) + ' allow=' + allow_value + ' high-risk=' + ', '.join(sorted(set(risky_features))))

        if len(findings) > 0:
            issues.append(self.makeIssueRecord(
                'Cross-origin iframe allows high-risk browser feature',
                'One or more cross-origin iframe elements allow high-risk browser features:<pre>' + self.htmlEscape('\n'.join(findings[:20])) + '</pre><p>' + self.htmlEscape(parent_policy_summary) + '</p>',
                'Low',
                'Firm',
                'Permissions-Policy can delegate browser feature access to embedded content through iframe allow attributes. This is legitimate for some integrations, but it increases the trust placed in cross-origin content.',
                'Review each iframe integration. Remove high-risk features from the iframe allow attribute unless required. Where required, pair the iframe allow attribute with a restrictive parent Permissions-Policy header that only delegates to the intended trusted origin.'
            ))

        return issues

    def getConfiguredDenyDirectives(self):
        try:
            raw = self.denyDirectiveList.getText()
        except Exception:
            raw = ''
        values = []
        for item in str(raw).split(','):
            item = item.strip().lower()
            if item:
                values.append(item)
        return values

    def isHtmlDocument(self, reqURL, headers):
        content_types = self.getHeaderValues(headers, 'Content-Type')
        for content_type in content_types:
            lower = content_type.lower()
            if 'text/html' in lower or 'application/xhtml+xml' in lower:
                return True

        try:
            path = str(reqURL.getPath()).lower()
        except Exception:
            path = str(reqURL).split('?')[0].lower()

        if path.endswith('.html') or path.endswith('.htm') or path.endswith('/'):
            return True

        # Treat extensionless paths as document-like. This catches many routed SPAs.
        last_segment = path.rsplit('/', 1)[-1]
        if '.' not in last_segment:
            return True

        return False

    def getStatusCode(self, headers, responseInfo):
        try:
            return int(responseInfo.getStatusCode())
        except Exception:
            pass

        if len(headers) > 0:
            match = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d+)', str(headers[0]))
            if match:
                try:
                    return int(match.group(1))
                except Exception:
                    return 0
        return 0

    def getHeaderValues(self, headers, header_name):
        values = []
        target = header_name.lower()
        for header in headers:
            if ':' not in header:
                continue
            name, value = header.split(':', 1)
            if name.strip().lower() == target:
                values.append(value.strip())
        return values

    def splitOutsideQuotesAndParens(self, value, delimiter):
        parts = []
        buf = []
        depth = 0
        in_quote = False
        escape = False

        for ch in value:
            if ch == '"' and not escape:
                in_quote = not in_quote

            if not in_quote:
                if ch == '(':
                    depth += 1
                elif ch == ')' and depth > 0:
                    depth -= 1
                elif ch == delimiter and depth == 0:
                    parts.append(''.join(buf))
                    buf = []
                    escape = False
                    continue

            buf.append(ch)
            escape = (ch == '\\' and not escape)

        parts.append(''.join(buf))
        return parts

    def tokenizeAllowlist(self, value):
        return re.findall(r'"[^"]+"|\'[^\']+\'|\S+', value)

    def getHtmlAttribute(self, tag, attribute_name):
        pattern = r'\b' + re.escape(attribute_name) + r'\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)'
        match = re.search(pattern, tag, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        value = match.group(1).strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        return value

    def parseIframeAllowFeatures(self, allow_value):
        features = []
        parts = self.splitOutsideQuotesAndParens(allow_value, ';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            # iframe allow syntax starts each directive with the feature name.
            feature = part.split()[0].strip().lower()
            feature = re.sub(r'[^a-z0-9-]', '', feature)
            if feature:
                features.append(feature)
        return features

    def getOriginFromUrl(self, url):
        try:
            protocol = str(url.getProtocol()).lower()
            host = str(url.getHost()).lower()
            port = int(url.getPort())
            if port == -1:
                return protocol + '://' + host
            return protocol + '://' + host + ':' + str(port)
        except Exception:
            return None

    def getOriginFromSrc(self, parent_origin, src_value):
        if src_value is None:
            return None

        src = src_value.strip()
        if src == '' or src.startswith('#'):
            return None

        if src.startswith('//'):
            if parent_origin is None:
                return None
            scheme = parent_origin.split('://')[0]
            src = scheme + ':' + src

        match = re.match(r'^(https?)://([^/:?#]+)(:\d+)?', src, flags=re.IGNORECASE)
        if match:
            scheme = match.group(1).lower()
            host = match.group(2).lower()
            port = match.group(3) or ''
            return scheme + '://' + host + port

        # Relative iframe source inherits the parent origin.
        return parent_origin

    def makeIssueRecord(self, name, detail, severity, confidence, background, remediation):
        return {
            'name': name,
            'detail': detail,
            'severity': severity,
            'confidence': confidence,
            'background': background,
            'remediation': remediation
        }

    def deduplicateIssueRecords(self, records):
        seen = {}
        output = []
        for record in records:
            key = record['name'] + '|' + record['detail']
            if key in seen:
                continue
            seen[key] = True
            output.append(record)
        return output

    def htmlEscape(self, value):
        if value is None:
            return ''
        text = str(value)
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        return text


class issue(IScanIssue):
    def __init__(self, httpService, reqURL, httpMessages, issueName, issueDetail, issueSeverity, issueConfidence, issueBackground, remediationDetail, remediationBackground):
        self._issueName = issueName
        self._httpService = httpService
        self._url = reqURL
        self._httpMessages = httpMessages
        self._issueDetail = issueDetail
        self._issueBackground = issueBackground
        self._severity = issueSeverity
        self._confidence = issueConfidence
        self._remediationDetail = remediationDetail
        self._remediationBackground = remediationBackground
        self._issueType = int(134217728)

    def getConfidence(self):
        return self._confidence

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return self._issueBackground

    def getIssueDetail(self):
        return self._issueDetail

    def getIssueName(self):
        return self._issueName

    def getIssueType(self):
        return self._issueType

    def getRemediationBackground(self):
        return self._remediationBackground

    def getRemediationDetail(self):
        return self._remediationDetail

    def getSeverity(self):
        return self._severity

    def getUrl(self):
        return self._url
