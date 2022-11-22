package invoice

import (
	_ "embed"
	"fmt"
	"io"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

type Invoice struct {
	Id           int
	Amount       string
	Source       string
	Created      string
	ValidThru    string
	BillTo       string
	BillFromHead string
	BillFromTail []string
}

//go:embed fonts/RobotoMono-Regular.ttf
var monospaceRegular []byte

//go:embed fonts/RobotoMono-Bold.ttf
var monospaceBold []byte

func (i *Invoice) Generate(w io.Writer) error {

	margin := 20.0
	indent := 10.0

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTopMargin(25)
	pdf.SetLeftMargin(margin)
	pdf.SetRightMargin(margin)
	pdf.SetTitle("sr.ht subscription invoice", true)
	pdf.AddPage()
	pdf.AddUTF8FontFromBytes("monospace", "", monospaceRegular)
	pdf.AddUTF8FontFromBytes("monospace", "B", monospaceBold)

	pageWidth, _ := pdf.GetPageSize()
	rightBorder := pageWidth - margin

	drawLine := func() {
		y := pdf.GetY()
		pdf.MoveTo(margin, y)
		pdf.LineTo(pageWidth-margin, y)
		pdf.ClosePath()
		pdf.SetLineWidth(0.3)
		pdf.DrawPath("B")
	}

	if i.BillFromHead != "" {
		pdf.SetFont("monospace", "B", 16)
		_, fs := pdf.GetFontSize()

		pdf.CellFormat(40, fs+2, i.BillFromHead, "0", 1, "L", false, 0, "")
	}

	pdf.SetFont("monospace", "", 11)
	_, fs := pdf.GetFontSize()

	for _, line := range i.BillFromTail {
		pdf.CellFormat(50, fs+1, line, "0", 1, "L", false, 0, "")
	}

	pdf.SetFont("monospace", "B", 11)
	_, fs = pdf.GetFontSize()

	pdf.SetX(rightBorder - 50)
	pdf.CellFormat(50, fs+1, fmt.Sprintf("Invoice #%d", i.Id), "0", 1, "R", false, 0, "")

	pdf.SetFont("monospace", "", 11)
	_, fs = pdf.GetFontSize()

	pdf.SetX(rightBorder - 50)
	pdf.CellFormat(50, fs, fmt.Sprintf("Issued %s", i.Created), "0", 1, "R", false, 0, "")
	pdf.Ln(-1)

	drawLine()
	//y := pdf.GetY()
	//pdf.MoveTo(margin, y)
	//pdf.LineTo(pageWidth-margin, y)
	//pdf.ClosePath()
	//pdf.SetLineWidth(0.3)
	//pdf.DrawPath("B")

	pdf.Ln(-1)

	for _, item := range []struct{ k, v string }{
		{"Service", "sr.ht subscription fee"},
		{"Amount", i.Amount},
		{"Paid with", i.Source},
		{"Paid on", i.Created},
		{"Valid for service thru", i.ValidThru},
	} {
		pdf.CellFormat(50, fs+1, item.k, "0", 1, "L", false, 0, "")
		pdf.SetX(margin + indent)
		pdf.CellFormat(50, fs+1, item.v, "0", 1, "L", false, 0, "")
	}

	pdf.Ln(-1)

	drawLine()
	//y = pdf.GetY()
	//pdf.MoveTo(margin, y)
	//pdf.LineTo(pageWidth-margin, y)
	//pdf.ClosePath()
	//pdf.SetLineWidth(0.3)
	//pdf.DrawPath("B")

	pdf.Ln(-1)

	pdf.SetFont("monospace", "B", 11)
	_, fs = pdf.GetFontSize()

	pdf.CellFormat(50, fs+1, "Invoice to:", "0", 1, "L", false, 0, "")

	pdf.Ln(-1)

	pdf.SetFont("monospace", "", 11)
	_, fs = pdf.GetFontSize()

	for _, line := range strings.Split(i.BillTo, "\n") {
		pdf.CellFormat(50, fs+1, line, "0", 1, "L", false, 0, "")
	}

	return pdf.Output(w)
}

//func main() {
//	Generate(123456, "$20.00", "Visa ending in 1337", "2022-05-14", "2023-05-14", "Conrad Hoffmann\nStephanstraße 51\n10559 Berlin", "sr.ht", "117 N. 15th Street\nPhiladelphia, PA 19102\nUnited States")
//}
