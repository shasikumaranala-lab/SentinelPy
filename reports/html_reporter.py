from pathlib import Path
from datetime import datetime
from collections import Counter
from dataclasses import asdict


class HTMLReport:

    def generate(
        self,
        suspicious_events,
        output_path: Path,
        statistics=None,
        timeline=None,
    ):

        template = self.load_template()
        css = self.load_css()

        html = (
            template
            .replace("{{STYLE}}", css)
            .replace("{{HEADER}}", self.build_header())
            .replace(
                "{{SUMMARY}}",
                self.build_summary(
                    suspicious_events,
                    statistics,
                ),
            )
            .replace(
                "{{STATISTICS}}",
                self.build_statistics(
                    statistics,
                ),
            )
            .replace(
                "{{THREATS}}",
                self.build_threat_table(
                    suspicious_events,
                ),
            )
            .replace(
                "{{TIMELINE}}",
                self.build_timeline(
                    timeline,
                ),
            )
            .replace(
                "{{FOOTER}}",
                self.build_footer(),
            )
        )

        output_path.write_text(
            html,
            encoding="utf-8",
        )

    ####################################################################
    # Template
    ####################################################################

    def load_template(self):

        template_path = (
            Path(__file__).parent
            / "templates"
            / "report_template.html"
        )

        return template_path.read_text(
            encoding="utf-8",
        )

    ####################################################################
    # CSS
    ####################################################################

    def load_css(self):

        css_path = (
            Path(__file__).parent
            / "templates"
            / "style.css"
        )

        return css_path.read_text(
            encoding="utf-8",
        )

    ####################################################################
    # Header
    ####################################################################

    def build_header(self):

        return f"""
<h1>SentinelPy Security Report</h1>

<p>
Generated :
{datetime.now().strftime("%d-%m-%Y %H:%M:%S")}
</p>
"""

    ####################################################################
    # Summary
    ####################################################################

    def build_summary(
        self,
        suspicious_events,
        statistics,
    ):

        total_events = statistics.total_events

        threats = len(suspicious_events)

        high = sum(
            1
            for event in suspicious_events
            if event.severity.name == "HIGH"
        )

        clean = max(
            total_events - threats,
            0,
        )

        return f"""
<div class="card">
<h3>{total_events}</h3>
<p>Events Processed</p>
</div>

<div class="card">
<h3>{threats}</h3>
<p>Threats Detected</p>
</div>

<div class="card">
<h3>{high}</h3>
<p>High Severity</p>
</div>

<div class="card">
<h3>{clean}</h3>
<p>Safe Events</p>
</div>
"""

    ####################################################################
    # Statistics
    ####################################################################

    def build_statistics(
        self,
        statistics,
    ):

        html = ""

        stats = asdict(statistics)


        for key, value in stats.items():

            html += f"""
<div class="stat-item">

<h3>{key.replace('_',' ').title()}</h3>

<p>{value}</p>

</div>
"""

        return f"""
<div class="statistics-box">

{html}

</div>
"""

    ####################################################################
    # Threat Table
    ####################################################################

    def build_threat_table(
        self,
        suspicious_events,
    ):

        rows = ""

        for event in suspicious_events:

            severity = event.severity.name

            badge = severity.lower()

            rows += f"""
<tr>

<td>

<span class="badge {badge}">
{severity}
</span>

</td>

<td>{event.detection_name}</td>

<td>{event.source_ip or "-"}</td>

<td>{event.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>

<td>{event.description}</td>

</tr>
"""

        return f"""
<table>

<thead>

<tr>

<th>Severity</th>

<th>Rule</th>

<th>Source IP</th>

<th>Timestamp</th>

<th>Description</th>

</tr>

</thead>

<tbody>

{rows}

</tbody>

</table>
"""

    ####################################################################
    # Timeline
    ####################################################################

    def build_timeline(
        self,
        timeline,
    ):

        html = ""

        for item in timeline:

            html += f"""
<div class="timeline-item">

<div class="timeline-time">

{item.timestamp.strftime("%Y-%m-%d %H:%M:%S")}

</div>

<div>

{item.description}

</div>

</div>
"""

        return f"""
<div class="timeline">

{html}

</div>
"""

    ####################################################################
    # Footer
    ####################################################################

    def build_footer(self):

        return """
<p>

Generated by SentinelPy

</p>

<p>

Version 1.0.0

</p>

<p>

Python Security Log Analysis Platform

</p>
"""