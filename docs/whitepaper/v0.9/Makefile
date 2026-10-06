PDF=kedgeflow-whitepaper
PATH:=/Library/TeX/texbin:$(PATH)
export PATH

.PHONY: paper deliverables
paper:
	mkdir -p build
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=$(PDF) -output-directory=build main.tex
	bibtex build/$(PDF)
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=$(PDF) -output-directory=build main.tex
	pdflatex -interaction=nonstopmode -halt-on-error -jobname=$(PDF) -output-directory=build main.tex

deliverables: paper
	mkdir -p output/pdf
	cp build/$(PDF).pdf output/pdf/$(PDF).pdf
