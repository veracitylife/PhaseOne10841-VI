<?php
/**
 * PhaseOne10841 / Veracity Integrity — Hire intake mailer
 * POST → email to info@veracityintegrity.com
 * DEFENSIVE ONLY. No secrets should be submitted.
 */
declare(strict_types=1);

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function h(string $s): string {
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function clean_line(?string $v, int $max = 200): string {
  $v = trim((string) $v);
  $v = preg_replace('/[\r\n]+/', ' ', $v) ?? $v;
  if (strlen($v) > $max) {
    $v = substr($v, 0, $max);
  }
  return $v;
}

function redirect_with(string $status): void {
  $target = '/hire.html?submitted=' . rawurlencode($status) . '#intake';
  header('Location: ' . $target, true, 303);
  exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  header('Location: /hire.html#intake', true, 303);
  exit;
}

// Honeypot — bots fill "website"
if (!empty($_POST['website'])) {
  redirect_with('ok');
}

$name = clean_line($_POST['name'] ?? '', 120);
$email = clean_line($_POST['email'] ?? '', 160);
$organization = clean_line($_POST['organization'] ?? '', 160);
$phone = clean_line($_POST['phone'] ?? '', 40);
$preferred = clean_line($_POST['preferred_contact'] ?? 'email', 40);
$interest = clean_line($_POST['interest'] ?? '', 80);
$environment = clean_line($_POST['environment'] ?? '', 40);
$timeline = clean_line($_POST['timeline'] ?? '', 40);
$stack = clean_line($_POST['stack'] ?? '', 240);
$budget = clean_line($_POST['budget_band'] ?? '', 40);
$summary = trim((string) ($_POST['summary'] ?? ''));
if (strlen($summary) > 4000) {
  $summary = substr($summary, 0, 4000);
}
$summary = str_replace(["\r\n", "\r"], "\n", $summary);

$topics = $_POST['topics'] ?? [];
if (!is_array($topics)) {
  $topics = [];
}
$topics = array_map(static fn($t) => clean_line((string) $t, 40), $topics);
$topics = array_values(array_filter($topics));

$defensive = ($_POST['defensive_only'] ?? '') === 'yes';
$agree = ($_POST['agree_terms'] ?? '') === 'yes';

if ($name === '' || $email === '' || $interest === '' || $summary === '' || !$defensive || !$agree) {
  redirect_with('invalid');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  redirect_with('invalid');
}

$to = 'info@veracityintegrity.com';
$subject = 'Hire intake: ' . $interest . ' — ' . $name;
$subject = preg_replace('/[\r\n]+/', ' ', $subject) ?? $subject;

$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$ua = clean_line($_SERVER['HTTP_USER_AGENT'] ?? '', 240);
$when = gmdate('c');

$body = "PhaseOne10841 / Veracity Integrity — For Hire Services intake\n";
$body .= "Submitted (UTC): {$when}\n";
$body .= "Source IP: {$ip}\n";
$body .= "User-Agent: {$ua}\n";
$body .= "Form: phaseone-hire-intake\n";
$body .= "--------------------------------------------------\n";
$body .= "Name: {$name}\n";
$body .= "Email: {$email}\n";
$body .= "Organization: {$organization}\n";
$body .= "Phone: {$phone}\n";
$body .= "Preferred contact: {$preferred}\n";
$body .= "Interest: {$interest}\n";
$body .= "Topics: " . (count($topics) ? implode(', ', $topics) : '(none)') . "\n";
$body .= "Environment: {$environment}\n";
$body .= "Timeline: {$timeline}\n";
$body .= "Stack: {$stack}\n";
$body .= "Budget band: {$budget}\n";
$body .= "Defensive-only confirmed: yes\n";
$body .= "Terms agreed: yes\n";
$body .= "--------------------------------------------------\n";
$body .= "Summary:\n{$summary}\n";
$body .= "--------------------------------------------------\n";
$body .= "Reply to the submitter email. Do not request secrets via this thread without a secure channel.\n";
$body .= "Public repo: https://github.com/veracitylife/PhaseOne10841-VI\n";

$headers = [];
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'From: PhaseOne Hire Form <noreply@veracityintegrity.com>';
$headers[] = 'Reply-To: ' . $email;
$headers[] = 'X-Mailer: PhaseOne10841-HireForm';

$ok = @mail($to, $subject, $body, implode("\r\n", $headers));

redirect_with($ok ? 'ok' : 'error');
