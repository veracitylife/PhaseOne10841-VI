<?php
/**
 * PhaseOne10841 / Veracity Integrity — Hire intake mailer
 * POST to the Veracity Integrity inquiry inbox
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

function form_value(string $key): string {
  $value = $_POST[$key] ?? '';
  return is_string($value) ? $value : '';
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

$name = clean_line(form_value('name'), 120);
$email = clean_line(form_value('email'), 160);
$organization = clean_line(form_value('organization'), 160);
$phone = clean_line(form_value('phone'), 40);
$preferred = clean_line(form_value('preferred_contact') ?: 'email', 40);
$interest = clean_line(form_value('interest'), 80);
$environment = clean_line(form_value('environment'), 40);
$timeline = clean_line(form_value('timeline'), 40);
$stack = clean_line(form_value('stack'), 240);
$agentCount = clean_line(form_value('agent_count'), 40);
$hosting = clean_line(form_value('hosting'), 80);
$currentChallenges = trim(form_value('current_challenges'));
if (strlen($currentChallenges) > 2500) {
  $currentChallenges = substr($currentChallenges, 0, 2500);
}
$currentChallenges = str_replace(["\r\n", "\r"], "\n", $currentChallenges);
$budget = clean_line(form_value('budget_band'), 40);
$summary = trim(form_value('summary'));
if (strlen($summary) > 4000) {
  $summary = substr($summary, 0, 4000);
}
$summary = str_replace(["\r\n", "\r"], "\n", $summary);

$topics = $_POST['topics'] ?? [];
if (!is_array($topics)) {
  $topics = [];
}
$topics = array_map(static fn($t) => is_string($t) ? clean_line($t, 40) : '', $topics);
$topics = array_values(array_filter($topics));

$defensive = form_value('defensive_only') === 'yes';
$agree = form_value('agree_terms') === 'yes';

if ($name === '' || $email === '' || $interest === '' || $summary === '' || !$defensive || !$agree) {
  redirect_with('invalid');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
  redirect_with('invalid');
}

$to = 'info@veracityintegrity.com';
$subject = 'Hire intake: ' . $interest . ' — ' . $name;
$subject = preg_replace('/[\r\n]+/', ' ', $subject) ?? $subject;

$when = gmdate('c');

$body = "PhaseOne10841 / Veracity Integrity — For Hire Services intake\n";
$body .= "Submitted (UTC): {$when}\n";
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
$body .= "Approximate agent/workload count: {$agentCount}\n";
$body .= "Hosting: {$hosting}\n";
$body .= "Stack: {$stack}\n";
$body .= "Budget band: {$budget}\n";
$body .= "Defensive-only confirmed: yes\n";
$body .= "Terms agreed: yes\n";
$body .= "--------------------------------------------------\n";
$body .= "Summary:\n{$summary}\n";
$body .= "Current concerns / requested controls:\n" . ($currentChallenges !== '' ? $currentChallenges : '(not provided)') . "\n";
$body .= "--------------------------------------------------\n";
$body .= "Reply to the submitter email. Do not request secrets via this thread without a secure channel.\n";
$body .= "Public repo: https://github.com/veracitylife/PhaseOne10841-VI\n";

$headers = [];
$headers[] = 'MIME-Version: 1.0';
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'From: PhaseOne10841 Hire Intake <info@veracityintegrity.com>';
$headers[] = 'Reply-To: ' . $email;
$headers[] = 'X-Mailer: PhaseOne10841-HireForm';

$ok = @mail($to, $subject, $body, implode("\r\n", $headers));

redirect_with($ok ? 'ok' : 'error');
