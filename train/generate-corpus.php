<?php

declare(strict_types=1);

// Self-distillation corpus builder for the honeypot LLM experiment.
// For many plausible unknown paths, ask the CURRENT model (full production prompt + GBNF grammar)
// for a clean fake page, sanitize it, and write a training pair whose PROMPT is minimal (a bare
// "METHOD /path" with a one-line system instruction) and whose COMPLETION is that HTML. Training on
// this teaches a fresh model to emit the same clean HTML from a bare prompt — no exemplar, no grammar.
// No nuclei matcher strings are involved, so it sidesteps the fingerprint trap.

require '/Users/bobmaher/myrepos/funnypot/vendor/autoload.php';

use Funnypot\App\Llm\LlmClient;
use Funnypot\App\Llm\LlmOutputSanitizer;
use Funnypot\App\Llm\LlmPromptBuilder;

$out = '/private/tmp/claude-501/-Users-bobmaher-repos-iCabbiTools/61030cef-7eda-45e1-964a-9af13ddb278e/scratchpad/train';
@mkdir($out, 0777, true);
$jsonl = fopen($out . '/pairs.jsonl', 'w');

$grammar = (string) file_get_contents('/Users/bobmaher/myrepos/funnypot/resources/llm/html.gbnf');
$prompt = new LlmPromptBuilder();
$client = new LlmClient('http://127.0.0.1:18080/completion', 30000, 320);
$san = new LlmOutputSanitizer();

// Varied, realistic-looking internal apps + resources + extensions → a broad path distribution.
$apps = ['acme-crm', 'vendor-portal', 'internal-wiki', 'billing-system', 'hr-portal', 'support-desk',
    'inventory-mgr', 'analytics', 'partner-api', 'field-ops', 'procurement', 'fleet-tracker',
    'payroll', 'helpdesk', 'crm', 'intranet', 'warehouse', 'logistics', 'compliance', 'onboarding',
    'contracts', 'timesheets', 'expenses', 'assets', 'tickets', 'knowledge-base', 'devportal', 'status'];
$resources = ['login', 'dashboard', 'settings', 'users', 'reports', 'export', 'admin', 'profile',
    'orders', 'invoices', 'search', 'upload', 'account', 'billing', 'members', 'documents', 'api/v2/orders',
    'api/v3/customers', 'reports/quarterly', 'admin/users', 'auth/signin', 'portal/home', 'files/download'];
$exts = ['', '', '.php', '.aspx', '.jsp', '/', '.do', '.action'];

// Build a deduped set of paths.
$paths = [];
foreach ($apps as $a) {
    foreach ($resources as $r) {
        $ext = $exts[(crc32($a . $r) % count($exts))];
        $paths['/' . $a . '/' . $r . $ext] = true;
    }
}
$paths = array_keys($paths);
shuffle($paths);
$target = (int) ($argv[1] ?? 220);
$paths = array_slice($paths, 0, $target);

// Minimal training prompt: a fixed one-line system instruction + the bare request. No exemplar,
// no grammar — that scaffolding is exactly what fine-tuning should let us drop.
$minimalPrompt = static function (string $method, string $path): string {
    return "<|im_start|>system\nYou are a web server. Output only the raw HTML the page at the requested path returns.<|im_end|>\n"
        . "<|im_start|>user\n{$method} {$path}<|im_end|>\n<|im_start|>assistant\n";
};

$ok = 0;
$fail = 0;
foreach ($paths as $i => $path) {
    $raw = $client->generate($prompt->build('GET', $path), $grammar);
    $html = $raw !== null ? $san->sanitize($raw) : null;
    if ($html === null) {
        $fail++;
        fwrite(STDERR, "skip $path\n");
        continue;
    }
    $line = json_encode([
        'prompt' => $minimalPrompt('GET', $path),
        'completion' => $html . '<|im_end|>',
    ], JSON_UNESCAPED_SLASHES);
    fwrite($jsonl, $line . "\n");
    $ok++;
    if ($ok % 20 === 0) {
        fwrite(STDERR, "generated $ok (fail $fail) / " . count($paths) . "\n");
    }
}
fclose($jsonl);
fwrite(STDERR, "DONE: $ok pairs written, $fail skipped -> $out/pairs.jsonl\n");
