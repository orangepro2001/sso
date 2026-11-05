<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\OauthClient;
use App\Services\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\View\View;

/**
 * OAuth client registration. Registration is the consent step in this design:
 * only an administrator can create a client, so authorized applications never
 * have to show a consent screen to the user.
 */
class ClientController extends Controller
{
    public function __construct(private readonly AuditLogger $audit) {}

    public function index(): View
    {
        return view('admin.clients.index', [
            'clients' => OauthClient::query()->latest('id')->paginate(25),
        ]);
    }

    public function create(): View
    {
        return view('admin.clients.create', [
            'scopes' => array_keys((array) config('sso.scopes', [])),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $this->validateClient($request);

        $plainSecret = null;
        $type = $data['type'];

        $client = OauthClient::create([
            'client_id' => OauthClient::generateClientId(),
            'name' => $data['name'],
            'type' => $type,
            'secret_hash' => null,
            'redirect_uris' => $this->uris($data['redirect_uris'] ?? ''),
            'allowed_scopes' => array_values(array_intersect(
                $data['allowed_scopes'] ?? [],
                array_keys((array) config('sso.scopes', [])),
            )),
            'active' => (bool) ($data['active'] ?? true),
            'created_by' => Auth::guard('admin')->id(),
            'note' => $data['note'] ?? null,
            'home_url' => $data['home_url'] ?? null,
            'sort_order' => (int) ($data['sort_order'] ?? 0),
            'in_launcher' => (bool) ($data['in_launcher'] ?? true),
        ]);

        if ($type === OauthClient::TYPE_CONFIDENTIAL) {
            $plainSecret = Str::random(48);
            $client->forceFill(['secret_hash' => password_hash($plainSecret, PASSWORD_DEFAULT)])->save();
        }

        $this->audit->log('admin.client.created', 'admin', Auth::guard('admin')->id(), 'client', $client->client_id, [
            'type' => $type, 'scopes' => $client->allowed_scopes,
        ], $request);

        return redirect()->route('admin.clients.edit', $client)
            ->with('status', 'Client registered.')
            // The secret is shown exactly once, straight after creation.
            ->with('client_secret', $plainSecret);
    }

    public function edit(OauthClient $client): View
    {
        return view('admin.clients.edit', [
            'client' => $client,
            'scopes' => array_keys((array) config('sso.scopes', [])),
        ]);
    }

    public function update(Request $request, OauthClient $client): RedirectResponse
    {
        $data = $this->validateClient($request);

        $client->fill([
            'name' => $data['name'],
            'type' => $data['type'],
            'redirect_uris' => $this->uris($data['redirect_uris'] ?? ''),
            'allowed_scopes' => array_values(array_intersect(
                $data['allowed_scopes'] ?? [],
                array_keys((array) config('sso.scopes', [])),
            )),
            'active' => (bool) ($data['active'] ?? false),
            'note' => $data['note'] ?? null,
            'home_url' => $data['home_url'] ?? null,
            'sort_order' => (int) ($data['sort_order'] ?? 0),
            'in_launcher' => (bool) ($data['in_launcher'] ?? false),
        ]);

        $plainSecret = null;
        if ($request->boolean('rotate_secret') && $client->type === OauthClient::TYPE_CONFIDENTIAL) {
            $plainSecret = Str::random(48);
            $client->secret_hash = password_hash($plainSecret, PASSWORD_DEFAULT);
        }

        $client->save();

        $this->audit->log('admin.client.updated', 'admin', Auth::guard('admin')->id(), 'client', $client->client_id, [
            'active' => $client->active, 'secret_rotated' => $plainSecret !== null,
        ], $request);

        return redirect()->route('admin.clients.edit', $client)
            ->with('status', 'Client updated.')
            ->with('client_secret', $plainSecret);
    }

    /**
     * @return array<string, mixed>
     */
    private function validateClient(Request $request): array
    {
        return $request->validate([
            'name' => ['required', 'string', 'max:120'],
            'type' => ['required', Rule::in([OauthClient::TYPE_PUBLIC, OauthClient::TYPE_CONFIDENTIAL])],
            'redirect_uris' => ['nullable', 'string', 'max:4000'],
            'allowed_scopes' => ['nullable', 'array'],
            'allowed_scopes.*' => ['string'],
            'active' => ['nullable', 'boolean'],
            'note' => ['nullable', 'string', 'max:2000'],
            // The launcher: where a person goes to use the application, in what order.
            'home_url' => ['nullable', 'url', 'max:500'],
            'sort_order' => ['nullable', 'integer', 'min:0', 'max:999'],
            'in_launcher' => ['nullable', 'boolean'],
        ]);
    }

    /**
     * One URI per line. No wildcards, no fragments: an authorization server only
     * ever redirects to an exact, pre-registered value.
     *
     * @return string[]
     */
    private function uris(string $raw): array
    {
        return collect(preg_split('/\R/', $raw) ?: [])
            ->map(fn ($line) => trim($line))
            ->filter(fn ($line) => $line !== '' && ! str_contains($line, '#'))
            ->values()
            ->all();
    }
}
