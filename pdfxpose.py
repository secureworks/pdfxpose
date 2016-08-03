#!/usr/bin/python

# Tool: pdfxpose - A security tool for detecting suspicious PDF modifications commonly found in BEC
# Author: James Bettke
# Copyright (C) 2016 SecureWorks

###  Dependencies  ###
# tesseract-ocr
# poppler-utils


import os
import re
import sys
import glob
import shutil
import tempfile
import subprocess
from pipes import quote

MAX_IMAGES =  100
BANKING_KEYWORDS = ['swift', 'iban', 'bic', 'rtgs']


# Accepts a path to a PDF file and returns the number of image streams it 
# contains. PDFs have been encountered that contain thousands of images 1 pixel 
# in height. Extracting those images takes far too long. Unfortunately the 
# current tool suite cannot selectively extract images.

# FIXME: find open source tools to overcome this problem.    
 
def pdf_image_count(path):
	proc = subprocess.Popen(['pdfimages', '-list', quote(path)], 
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()
	count = len(proc.stdout.readlines())
	return 0 if count < 2 else count - 2


# Split a PDF file by page with each being its own PDF file. Accepts a PDF file 
# path as input and a noutput directory path. Returns a list of paths to the PDF
# pages.

def split_pdf(input_pdf_path, output_dir):
	proc = subprocess.Popen(['pdfseparate', quote(input_pdf_path), quote(os.path.join(output_dir,'split_%d.pdf'))], 
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()

	files = []
	
	for f in os.listdir(output_dir):
		f = os.path.join(output_dir, f)
		if os.path.isfile(f):
			files.append(f)

	return sorted(files)

# Convert a single page PDF file to a PNG image. The first parameter is a file 
# path to the source PDF. The second parameter is destination path of the 
# created PNG. Returns the path the created PNG. 

def pdf2image(input_pdf_path, output_image_path):
	cmd = ['convert', 
		'-density', '300', 
		'-background', 'white',
		'-colorspace', 'Gray',
		'-gamma', '2.2',
		'-flatten',  
		quote(input_pdf_path), quote(output_image_path)]

	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()

	return output_image_path


# Performs Optical Character Recognition (OCR) on a given image provided the 
# file path. Returns the recognized text as a string. 

def ocr_image(input_path):
	proc = subprocess.Popen(['tesseract', quote(input_path), 'stdout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()
	return "".join(proc.stdout.readlines())


# Extracts and returns all text streams as a single string given the PDF file 
# path. 

def extract_text(input_pdf_path):
	proc = subprocess.Popen(['pdftotext', quote(input_pdf_path), '-'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()
	return "".join(proc.stdout.readlines())


# Extracts all image streams in PDF to a temporary directory inside the provided 
# directory. Returns a list of paths to the extracted streams.
# Example: /tmp/tmp.pdfxpose-kXp6kS/images- uG5rwQ

def extract_images(input_pdf_path, output_dir):

	image_dir = tempfile.mkdtemp(prefix='images-', dir=output_dir)

	proc = subprocess.Popen(['pdftohtml', quote(input_pdf_path) ,quote(os.path.join(image_dir,'output.html'))], 
		stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	proc.wait()

	images = []
	for ext in ['jpg','png','gif']:
		images += glob.glob(os.path.join(image_dir,'*.'+ext))
	return images


# Count the frequency of words in the word list that also appear within the 
# search text

def word_count(text, word_list):

	count = 0
	text = re.sub(r'\s+', '', text)

	for word in word_list:
		count += len(re.findall(word,text))

	return count

def set_status_message(message):
	sys.stderr.write('\r'+' '*80 )
	sys.stderr.write('\r'+message)
	sys.stderr.flush()


# Performs overlay artifact analysis on a PDF specified by file path. The PDF is
# split into separate pages. Text and images are extracted from each page, 
# OCR'd, and scored based on the presence of keywords commonly associated with 
# Business Email Compromise (BEC). Results are displayed to the standard output 
# stream.

def analyse_pdf(input_pdf_path):
	
	flat_text  = "" # Text visible after flattening / down merging layers into image 
	layer_text = "" # Combine text from all layers (text and OCR images)

	# Create a temporary directory to house working files
	tmp_dir = tempfile.mkdtemp(prefix='tmp.pdfxpose-')

	# Check to see how many image are in PDF, quit if too many (Or find faster way of proccessing )
	image_count = pdf_image_count(input_pdf_path)

	if image_count > MAX_IMAGES:
		print >> sys.stderr, "Error! Too many images to extract."
		return False

	# - Top layer algorithm - #
	# split the pdf
	set_status_message('Splitting PDF file...')
	pdf_pages = split_pdf(input_pdf_path, tmp_dir)

	for page in pdf_pages:

		# Flatten PDF page into a PNG image
		set_status_message('Flattening PDF...')
		flat_page = pdf2image(page, page + '.png')

		# OCR the flattened PDF (only text visible to the user)
		set_status_message('Performing OCR on PDF...')
		flat_text += ocr_image(flat_page)

		# - Hidden layer algorithm - #
		# extract text from all pdf layers
		set_status_message('Extracting text...')
		layer_text += extract_text(input_pdf_path)

		# extract all images and ocr
		set_status_message('Extracting images...')
		image_files = extract_images(page, tmp_dir)

		set_status_message('Performing OCR on images...')
		for image in image_files:
			layer_text += ocr_image(image)

	# end_for

	# Compare frequency of banking terms in both (case insensitive)
	flat_count  = word_count(flat_text.lower() , BANKING_KEYWORDS)
	layer_count = word_count(layer_text.lower(), BANKING_KEYWORDS)

	score = 0

	if layer_count > flat_count:
		score = 1
	
	print "\r%10d  %4d : %-7d  %-6d  %s" % (score, flat_count, layer_count, image_count, input_pdf_path)

	# Remove temporary directory
	set_status_message('Deleting temporary files...')
	shutil.rmtree(tmp_dir)

def main():
	
	banner = """
           _  __                            
          | |/ _|                           
 _ __   __| | |___  ___ __   ___  ___  ___  
| '_ \ / _` |  _\ \/ / '_ \ / _ \/ __|/ _ \ 
| |_) | (_| | |  >  <| |_) | (_) \__ \  __/ 
| .__/ \__,_|_| /_/\_\ .__/ \___/|___/\___| 
| |                  | |                    
|_|                  |_|                   """

	if len(sys.argv) < 2:
		print >> sys.stderr, "\n\tUsage: pdfxpose.py <FILE>...\n"
		sys.exit(1)

	# Iterate over remaining arguments. Any argument that is not a file 
	# will result in an error. 

	for arg in sys.argv[1:]:
		if not os.path.isfile(arg):
			print >> sys.stderr, "Invalid parameter! '%s' is not a file." % (arg)
			sys.exit(1)

	print banner

	print "\tJob size: %d\n" % (len(sys.argv[1:]))
	print "Suspicious  Flat : Layered  Images  Filename"
	print "-"*45

	for arg in sys.argv[1:]:
		analyse_pdf(arg)

if __name__ == "__main__":
	main()

