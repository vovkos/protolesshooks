use strict;

@ARGV || die("usage: nasm-list-to-cpp.pl <file>");
open(my $file, "<", $ARGV[0]) || die("Can't open ${ARGV[0]}");

# extract code bytes and assembly from a NASM listing

my @codeArray = ();
my @commentArray = ();
my $commentCol = 0;

while (!eof($file))
{
	my $line = <$file>;
	if ($line !~ m/
		\s*([0-9]+)\s+
		([0-9a-fA-F]+)\s+
		([0-9a-fA-F]+)?-?
		([\[\(]([0-9a-fA-F]+)[\]\)])?\s+
		(.*)
		/x)
	{
		next;
	}

	my $code = "$3$5";
	my $comment = "$2  $6";

	$code =~ s/([0-9a-fA-F]{2})/0x\1, /g;
	my $codeLength = length($code);
	if ($codeLength > $commentCol)
	{
		$commentCol = $codeLength;
	}

	push(@codeArray, $code);
	push(@commentArray, $comment);
}

# now print C-array with aligned comments

my $format = "%-${commentCol}s // %s\n";
my $count = @codeArray;

for (my $i = 0; $i < $count; $i++)
{
	my $code = $codeArray[$i];
	my $comment = $commentArray[$i];

	printf($format, $code, $comment);
}
