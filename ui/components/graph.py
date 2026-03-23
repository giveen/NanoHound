from __future__ import annotations

from typing import Any
from nicegui import ui


def create_graph_area(impl: Any) -> Any:
    """Create center graph echarts placeholder and attach to impl.chart_placeholder.

    Returns the chart component.
    """
    # Start with an empty option; the implementation's _refresh_chart will
    # populate it when data is available.
    # NiceGUI uses `ui.echart` (singular) for the ECharts component.
    chart = ui.echart({})
    chart.style("height: calc(100vh - 120px); width: 100%;")
    # expose the placeholder to the implementation so it can call
    # `chart.run_chart_method('setOption', options)` as before.
    impl.chart_placeholder = chart
    return chart


def format_graph_options(options: dict) -> dict:
    # Placeholder passthrough in case future formatting is necessary.
    return options
