<?php

namespace App\Http\Resources;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * One account as the API shows it. The note, last sign-in address and creator are
 * administrative detail and only reach a super administrator.
 *
 * @mixin User
 */
class UserResource extends JsonResource
{
    public static $wrap = null;

    public function toArray(Request $request): array
    {
        $viewer = $request->user();
        $admin = $viewer instanceof User && $viewer->isSuperAdmin();

        return [
            'id' => $this->id,
            'username' => $this->username,
            'name' => $this->name,
            'role' => $this->role,
            'status' => $this->status,
            'picture' => $this->avatarUrl(),
            'created_at' => $this->created_at?->toIso8601String(),
            'last_login_at' => $this->last_login_at?->toIso8601String(),
            $this->mergeWhen($admin, fn () => [
                'note' => $this->note,
                'last_login_ip' => $this->last_login_ip,
                'created_by' => $this->created_by,
            ]),
        ];
    }
}
