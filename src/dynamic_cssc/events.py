from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import StrEnum


class EventKind(StrEnum):
    SET = "set"
    QUERY = "query"
    VERSION = "version"


@dataclass(frozen=True, slots=True)
class Event:
    timestamp: float
    kind: EventKind
    row: int | None = None
    col: int | None = None
    value: int | None = None

    @classmethod
    def set(cls, timestamp: float, row: int, col: int, value: int) -> "Event":
        return cls(timestamp, EventKind.SET, row, col, value)

    @classmethod
    def query(cls, timestamp: float) -> "Event":
        return cls(timestamp, EventKind.QUERY)

    @classmethod
    def version(cls, timestamp: float) -> "Event":
        return cls(timestamp, EventKind.VERSION)


@dataclass(frozen=True, slots=True)
class NetUpdate:
    row: int
    col: int
    before: int
    after: int

    @property
    def is_noop(self) -> bool:
        return self.before == self.after


@dataclass(frozen=True, slots=True)
class PublicationWindow:
    index: int
    start_time: float
    end_time: float
    updates: tuple[NetUpdate, ...]
    reason: str


def publication_windows(
    events: Iterable[Event],
    initial_state: dict[tuple[int, int], int] | None = None,
    *,
    max_seconds: float,
    microbatch_max_updates: int,
    query_requires_latest: bool = True,
) -> Iterator[PublicationWindow]:
    """Net updates only inside one publication window.

    Query/version/freshness/microbatch boundaries flush the current window. The global
    matrix state is updated in event order, so netting never crosses a visibility boundary.
    """

    if max_seconds <= 0:
        raise ValueError("max_seconds must be positive")
    if microbatch_max_updates <= 0:
        raise ValueError("microbatch_max_updates must be positive")

    state = dict(initial_state or {})
    first_before: dict[tuple[int, int], int] = {}
    touched: set[tuple[int, int]] = set()
    start_time: float | None = None
    last_time: float | None = None
    index = 0
    update_events = 0

    def flush(end_time: float, reason: str) -> PublicationWindow | None:
        nonlocal index, start_time, update_events
        if not touched:
            start_time = None
            update_events = 0
            return None
        net = []
        for row, col in sorted(touched):
            before = first_before[(row, col)]
            after = state.get((row, col), 0)
            if before != after:
                net.append(NetUpdate(row, col, before, after))
        window = PublicationWindow(
            index=index,
            start_time=start_time if start_time is not None else end_time,
            end_time=end_time,
            updates=tuple(net),
            reason=reason,
        )
        index += 1
        touched.clear()
        first_before.clear()
        start_time = None
        update_events = 0
        return window

    for event in sorted(events, key=lambda item: item.timestamp):
        if last_time is not None and event.timestamp < last_time:
            raise ValueError("events must be nondecreasing in timestamp")
        last_time = event.timestamp

        if (
            start_time is not None
            and event.timestamp - start_time >= max_seconds
            and touched
        ):
            window = flush(start_time + max_seconds, "freshness")
            if window is not None:
                yield window

        if event.kind == EventKind.SET:
            if event.row is None or event.col is None or event.value is None:
                raise ValueError("set event requires row, col, and value")
            if start_time is None:
                start_time = event.timestamp
            coord = (event.row, event.col)
            if coord not in first_before:
                first_before[coord] = state.get(coord, 0)
            touched.add(coord)
            if event.value == 0:
                state.pop(coord, None)
            else:
                state[coord] = event.value
            update_events += 1
            if update_events >= microbatch_max_updates:
                window = flush(event.timestamp, "microbatch")
                if window is not None:
                    yield window
        elif event.kind == EventKind.QUERY and query_requires_latest:
            window = flush(event.timestamp, "query")
            if window is not None:
                yield window
        elif event.kind == EventKind.VERSION:
            window = flush(event.timestamp, "version")
            if window is not None:
                yield window

    if touched:
        window = flush(last_time if last_time is not None else 0.0, "end-of-stream")
        if window is not None:
            yield window
