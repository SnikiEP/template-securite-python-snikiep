from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

from src.tp1.utils.capture import Capture


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = []
        self.graph = None

    def concat_report(self) -> str:
        content = ""
        content += self.title
        content += self.summary
        return content

    def save(self, filename: str) -> None:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(filename, pagesize=A4)
        elements = []

        elements.append(Paragraph(self.title, styles["Title"]))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(self.summary, styles["Normal"]))
        elements.append(Spacer(1, 0.5 * cm))

        if self.array:
            elements.append(Table(self.array))
            elements.append(Spacer(1, 0.5 * cm))

        if self.graph:
            elements.append(self.graph)

        doc.build(elements)

    def generate(self, param: str) -> None:
        protocols = self.capture.protocols
        if not protocols:
            return

        if param == "graph":
            sorted_p = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
            labels = [p[0] for p in sorted_p]
            values = [p[1] for p in sorted_p]

            drawing = Drawing(400, 200)
            chart = VerticalBarChart()
            chart.x = 30
            chart.y = 20
            chart.width = 350
            chart.height = 160
            chart.data = [values]
            chart.categoryAxis.categoryNames = labels
            drawing.add(chart)
            self.graph = drawing

        elif param == "array":
            sorted_p = sorted(protocols.items(), key=lambda x: x[1], reverse=True)
            self.array = [["Protocol", "Count"]] + [[p, str(c)] for p, c in sorted_p]
