set terminal pdf
set output "l5.pdf"
set title "Mean Time Rule update = 5s" font ",14"
set datafile separator ","
set ylabel "error ration (%)" font ",14" textcolor rgb "black"
set xlabel "time elapsed (s)" font ",14" textcolor rgb "black"
set xrange [0:100]
set yrange [0:50]
set y2range [0:20] tc black
set y2label "Cumulated Security Rule Changes" textcolor rgb "black" font ",10"
set key font ",12" left top Left title 'Legend' box 3  
set grid ytics mytics  # draw lines for each ytics and mytics
set mytics 2           # set the spacing for the mytics
set grid               # enable the grid
plot "data.csv" using 0:2 lw 3 dt "." with lines title "SCO - flow conformance",\
     "data.csv" using 0:3 lw 3 dt "-" with lines title "SCO/Intent - flow conformance",\
	 "data.csv" using 0:4 lw 3 dt "._" with lines title "SCO/Intent - Intent conformance",\
	 "data.csv" using 0:5 lw 5 with lines title "Security Rules changes" axis x1y2
