//===================================================== file = genfile.c ====
//=  Program to generate file of specified size (filled with random bytes)  =
//===========================================================================
//=  Notes: 1) Writes to a user specified output file                       =
//=             * File format is binary                                     =
//=-------------------------------------------------------------------------=
//= Example execution:                                                      =
//=                                                                         =
//=   ---------------------------------------- genfile.c -----              =
//=   -  Program to generate a file with random contents of  -              =
//=   -  a specified size.  WARNING: Make sure there is      -              =
//=   -  enough disk space available for the file.           -              =
//=   --------------------------------------------------------              =
//=   Output file name ===================================> output.dat      =
//=   Specify file size (in bytes) =======================> 5               =
//=   --------------------------------------------------------              =
//=   -  Generating file                                     -              =
//=   --------------------------------------------------------              =
//=   --------------------------------------------------------              =
//=   -  Done!                                               -              =
//=   --------------------------------------------------------              =
//=-------------------------------------------------------------------------=
//=  Build: gcc genfile.c, bcc32 genfile.c, cl genfile.c                    =
//=-------------------------------------------------------------------------=
//=  Execute: genfile                                                       =
//=-------------------------------------------------------------------------=
//=  Author: Zane G. Reynolds                                               =
//=          University of South Florida                                    =
//=          WWW: http://www.csee.usf.edu/~zreynold                         =
//=          Email: zreynold@csee.usf.edu                                   =
//=-------------------------------------------------------------------------=
//=  History: ZGR (10/12/00) - Genesis                                      =
//===========================================================================

//----- Include files -------------------------------------------------------
#include <stdio.h>              // Needed for printf(), scanf(), and f*()
#include <stdlib.h>             // Needed for atoi() and rand()

//===== Main program ========================================================
void main(void)
{
  FILE     *fp;                 // File pointer to output file
  char     file_name[256];      // Output file name string
  int      max_size;            // File size specified by user
  char     temp_string[256];    // Temporary string variable
  int      i;                   // Loop counter

  // Output banner
  printf("---------------------------------------- genfile.c ----- \n");
  printf("-  Program to generate a file with random contents of  - \n");
  printf("-  a specified size.  WARNING: Make sure there is      - \n");
  printf("-  enough disk space available for the file.           - \n");
  printf("-------------------------------------------------------- \n");

  // Prompt for output filename and then create the file (write binary)
  printf("Output file name ===================================> ");
  scanf("%s", file_name);
  fp = fopen(file_name, "wb");
  if (fp == NULL)
  {
    printf("ERROR in creating output file (%s) \n", file_name);
    exit(1);
  }

  // Prompt desired file size
  printf("Specify file size (in bytes) =======================> ");
  scanf("%s", temp_string);
  max_size = atoi(temp_string);

  //Output message and generate file
  printf("-------------------------------------------------------- \n");
  printf("-  Generating file                                     - \n");
  printf("-------------------------------------------------------- \n");

  // Generate and output random byte values
  for (i=0; i<max_size; i++)
    fprintf(fp, "%c", (unsigned char) (rand() % 256));

  //Output message and close the output file
  printf("-------------------------------------------------------- \n");
  printf("-  Done!                                               - \n");
  printf("-------------------------------------------------------- \n");
  fclose(fp);
}
