pdfxpose
=====

pdfxpose - A Security tool for detecting suspicious PDF modifications commonly found in BEC

## Overview
While investigating Business Email Compromise (BEC), suspicious indicators were discovered in a majority of the PDFs encountered. This tool was developed to detect PDFs altered by threat actors engaging in BEC.

## Dependencies
Pdfxpose depends on poppler-utils 0.41.0+ for processing PDFs and Tesseract for performing Optical Character Recognition (OCR) on images. Both can be installed from the Ubuntu repositories.

```bash
root@host:~# apt-get update
root@host:~# apt-get install poppler-utils tesseract-ocr
```

## Usage
The tool accepts paths to one or more PDF files to be processed as command-line arguments. A mock BEC invoice has been provided as an example.

```bash
python pdfxpose.py Widgets_Order.pdf
```

## Interpreting the Output

```bash
Suspicious  Flat : Layered  Images  Filename
---------------------------------------------
```

The “suspicious” column displays either a positive or a negative detection result indicated by a 1 or 0. The PDF file is tested in two states. The flat state is an analysis of just the top layer simulating what the viewer of the document would see. The layered state entails extracting all text and images from a PDF regardless of layer. The results displayed in the flat and layered columns are frequencies of BEC keywords matched while analyzing the PDF in varying states. The images column is the number of images successfully extracted from the PDF.

