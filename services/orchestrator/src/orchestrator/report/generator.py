from rich.console import Console
from rich.table import Table

from orchestrator.db.connection import Database

console = Console()


class ReportGenerator:
    def __init__(self, db: Database):
        self._db = db

    def generate(self) -> None:
        with self._db.connection() as conn:
            rows = conn.execute("""
                SELECT 
                    cf.file_path,
                    sf.line_number,
                    sf.pattern_type,
                    sf.raw_severity,
                    lv.is_exploitable,
                    lv.confidence,
                    lv.false_positive_bool,
                    lv.reasoning_trace
                FROM llm_verifications lv
                JOIN static_findings sf ON sf.id = lv.finding_id
                JOIN codebase_files cf ON cf.id = sf.file_id
                ORDER BY sf.raw_severity DESC
            """).fetchall()

        if not rows:
            console.print("[yellow]No verified findings yet[/yellow]")
            console.print("[dim]Run 'orchestrator verify' first[/dim]")
            return

        table = Table(title="[bold]Vulnerability Report[/bold]")
        table.add_column("Severity", style="bold")
        table.add_column("File:Line", style="cyan")
        table.add_column("Pattern", style="magenta")
        table.add_column("Exploitable", style="green")
        table.add_column("Confidence")

        severity_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "green"
        }

        for row in rows:
            severity = row[3].lower()
            color = severity_colors.get(severity, "white")
            exploitable = "✅ Yes" if row[4] else "❌ No"
            
            table.add_row(
                f"[{color}]{row[3].upper()}[/{color}]",
                f"{row[0]}:{row[1]}",
                row[2],
                exploitable,
                f"{row[5]*100:.1f}%",
            )

        console.print(table)

        # Print reasoning traces
        console.print("\n[bold]📋 Reasoning Traces:[/bold]\n")
        for i, row in enumerate(rows, 1):
            console.print(f"[bold]{i}. {row[0]}:{row[1]}[/bold]")
            console.print(f"   Pattern: {row[2]}")
            console.print(f"   Exploitable: {'Yes' if row[4] else 'No'} (confidence: {row[5]*100:.1f}%)")
            console.print(f"   Reasoning: {row[7][:500]}...")
            console.print()