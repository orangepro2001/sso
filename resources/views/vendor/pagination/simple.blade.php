{{-- Deliberately dependency-free pagination: previous / page x of y / next --}}
@if ($paginator->hasPages())
    <ul class="pagination">
        @if ($paginator->onFirstPage())
            <li class="muted">Previous</li>
        @else
            <li><a href="{{ $paginator->previousPageUrl() }}" rel="prev">Previous</a></li>
        @endif

        <li class="active">Page {{ $paginator->currentPage() }} / {{ $paginator->lastPage() }}</li>

        @if ($paginator->hasMorePages())
            <li><a href="{{ $paginator->nextPageUrl() }}" rel="next">Next</a></li>
        @else
            <li class="muted">Next</li>
        @endif
    </ul>
@endif
