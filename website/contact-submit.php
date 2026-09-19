<?php
declare(strict_types=1);

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function contact_redirect(string $status): never {
    header('Location: /contact.html?submitted=' . rawurlencode($status) . '#contact-form', true, 303);
    exit;
}

function contact_clean(string $value, int $max, bool $multiline = false): string {
    $value = trim(strip_tags($value));
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
    if (!$multiline) {
        $value = preg_replace('/[\r\n]+/', ' ', $value) ?? $value;
    } else {
        $value = str_replace(["\r\n", "\r"], "\n", $value);
    }
    return mb_substr($value, 0, $max, 'UTF-8');
}

function contact_field(string $key): string {
    $value = $_POST[$key] ?? '';
    return is_string($value) ? $value : '';
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    contact_redirect('invalid');
}

if (contact_clean(contact_field('website'), 300) !== '') {
    // Quietly discard honeypot submissions.
    contact_redirect('ok');
}

$name = contact_clean(contact_field('name'), 120);
$email = contact_clean(contact_field('email'), 160);
$organization = contact_clean(contact_field('organization'), 160);
$phone = contact_clean(contact_field('phone'), 40);
$topic = contact_clean(contact_field('topic'), 80);
$message = contact_clean(contact_field('message'), 4000, true);
$consent = contact_field('consent') === 'yes';
$allowedTopics = [
    'PhaseOne product question', 'Demo or evaluation', 'Implementation or consulting',
    'Technical support', 'Partnership', 'Other',
];

if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || !in_array($topic, $allowedTopics, true) || $message === '' || !$consent) {
    contact_redirect('invalid');
}

$to = 'veracityintegrity_claw@veracityintegrity.com';
$subject = '[PhaseOne contact] ' . $topic;
$body = implode("\n", [
    'General inquiry submitted from phaseone10841.me/contact.html',
    'Submitted (UTC): ' . gmdate('Y-m-d H:i:s'),
    '',
    'Name: ' . $name,
    'Email: ' . $email,
    'Organization: ' . ($organization !== '' ? $organization : '(not provided)'),
    'Phone: ' . ($phone !== '' ? $phone : '(not provided)'),
    'Topic: ' . $topic,
    '',
    'Message:',
    $message,
    '',
    'The submitter agreed to use of their details to respond to this inquiry.',
    'Do not request credentials or secrets by reply email.',
]);

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'From: PhaseOne10841 Contact <veracityintegrity_claw@veracityintegrity.com>',
    'Reply-To: ' . $email,
    'X-Content-Type-Options: nosniff',
];

$sent = @mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, implode("\r\n", $headers));
contact_redirect($sent ? 'ok' : 'error');
