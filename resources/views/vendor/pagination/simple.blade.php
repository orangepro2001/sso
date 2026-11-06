{{-- Deliberately dependency-free pagination: previous / page x of y / next --}}
@if ($paginator->hasPages())
    <ul class="pagination">
        @if ($paginator->onFirstPage())
            <li class="muted">‹ 이전</li>
        @else
            <li><a href="{{ $paginator->previousPageUrl() }}" rel="prev">‹ 이전</a></li>
        @endif

        <li class="active">{{ $paginator->currentPage() }} / {{ $paginator->lastPage() }}</li>

        @if ($paginator->hasMorePages())
            <li><a href="{{ $paginator->nextPageUrl() }}" rel="next">다음 ›</a></li>
        @else
            <li class="muted">다음 ›</li>
        @endif
    </ul>
@endif
