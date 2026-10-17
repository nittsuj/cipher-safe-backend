#import "@preview/latexlike-report:1.0.0": *
#show: latexlike-report.with(
 
 // ======== Cover ============
 //Use content [] or none, except in author.
  author: "Justin Valentino", // must be a string ("")
  title: [Assignment Report I],
  subtitle: [
    Baskoro Adi Pratomo, S.Kom., M.Kom., Ph.D.
  ],
  
  participants: [
    5025241234 \
    Indra Wahyu Tirtayasa \
    5025241108 \
    Raymond Julius Pardosi \
    5025241268
    Denzel Daniels \
    5025241228
  ], // In case of several authors (the name in author parameter will go first) Use content [] or none.
  
  affiliation: [Institut Teknologi Sepuluh Nopember],
  year: [2026],
  class: [INFORMATION SECURITY - IUP],
  other: none,
  //date: [#datetime.today().display()], // You could use #datetime.today().display() for the date.
  date: [2026-10-21],
  logo: block(width: 100%, align(center, image("Images/its-logo.svg", width: 45%))),
  //==========Theme ===============
  theme-color: rgb("#0f2787"),
  lang: "en", 
   participants-supplement: "Author:", //Change it if you change the language
 
            
  //=========Font =================
  title-font: "New Computer Modern",
  font: "New Computer Modern",
  font-size : 13pt,
  font-weight: 400,
  //============ Math =============
  math-font: "New Computer Modern Math",
  math-weight: 400,
  math-ref-supplement: auto, //Use none for no supplement, auto for language based or any other function or string you like
  math-numbering: "(1.1)", // The numbering style you like
  
  // ---- Equate package ---
  // For more information, you can refer to equate documentation
  
  math-number-mode: "label", //Can be "label" or "line" 
  math-sub-numbering: true,  // true or false
  //===========Page style===============
  pagebreak-section: true, //For pagebreak after adding a new level one heading (=)
  show-outline:true, //true or false 
  page-paper:"a4",
  //-----chic header package----
  // customize the left/center/right header and left/center/right footer
  // you can add images, text, the number of the current page, etc, or put none if you don't want some part of the header or footer.
  //some usefull function: chic-page-number(), chic-heading-name()
  
  h-l : [#smallcaps[Assignment Report I]],
  h-r :[#image("Images/its-logo.svg",width: 14%)],
  h-c : none,
  f-l : [],
  f-r : [],
  f-c : chic-page-number(),
  //=======================================
  //For more customitation you can check the documentation. !! Enjoy :D !!
)

= Introduction
= Justification
= Analysis
= References