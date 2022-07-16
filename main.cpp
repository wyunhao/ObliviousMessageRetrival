#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/MRE.h"

using namespace seal;

int main() {
    cout << "+------------------------------------+" << endl;
    cout << "| Demos                              |" << endl;
    cout << "+------------------------------------+" << endl;
    cout << "| 1. OMD1p Detection Key Size        |" << endl;
    cout << "| 2. OMR1p/OMR2p Detection Key Size  |" << endl;
    cout << "| 3. OMD1p                           |" << endl;
    cout << "| 4. OMR1p Single Thread             |" << endl;
    cout << "| 5. OMR2p Single Thread             |" << endl;
    cout << "| 6. OMR1p Two Threads               |" << endl;
    cout << "| 7. OMR2p Two Threads               |" << endl;
    cout << "| 8. OMR1p Four Threads              |" << endl;
    cout << "| 9. OMR2p Four Threads              |" << endl;
    cout << "| 10.GOMR1 Single Thread             |" << endl;
    cout << "| 11.GOMR1 Two Threads               |" << endl;
    cout << "| 12.GOMR1 Four Threads              |" << endl;
    cout << "| 13.GOMR2 Single Thread             |" << endl;
    cout << "| 14.GOMR2 Two Threads               |" << endl;
    cout << "| 15.GOMR2 Four Threads              |" << endl;
    cout << "| 16.GOMR1_OM Single Thread          |" << endl;
    cout << "| 17.GOMR1_OM_BFV Single Threads     |" << endl;
    cout << "| 18.GOMR1_FG Single Thread          |" << endl;
    cout << "+------------------------------------+" << endl;

    int selection = 0;
    bool valid = true;
    do
    {
        cout << endl << "> Run demos (1 ~ 18) or exit (0): ";
        if (!(cin >> selection))
        {
            valid = false;
        }
        else if (selection < 0 || selection > 18)
        {
            valid = false;
        }
        else
        {
            valid = true;
        }
        if (!valid)
        {
            cout << "  [Beep~~] valid option: type 0 ~ 18" << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
        }
    } while (!valid);

    switch (selection)
        {
        case 1:
            OMDlevelspecificDetectKeySize();
            break;

        case 2:
            levelspecificDetectKeySize();
            break;

        case 3:
            numcores = 1;
            OMD1p();
            break;

        case 4:
            numcores = 1;
            OMR2();
            break;

        case 5:
            numcores = 1;
            OMR3();
            break;
        
        case 6:
            numcores = 2;
            OMR2();
            break;

        case 7:
            numcores = 2;
            OMR3();
            break;
        
        case 8:
            numcores = 4;
            OMR2();
            break;

        case 9:
            numcores = 4;
            OMR3();
            break;

        case 10:
            numcores = 1;
            GOMR1();
            break;

        case 11:
            numcores = 2;
            GOMR1();
            break;

        case 12:
            numcores = 4;
            GOMR1();
            break;

        case 13:
            numcores = 1;
            GOMR2();
            break;

        case 14:
            numcores = 2;
            GOMR2();
            break;

        case 15:
            numcores = 4;
            GOMR2();
            break;

        case 16:
            numcores = 1;
            GOMR1_ObliviousMultiplexer();
            break;

        case 17:
            numcores = 1;
            GOMR1_ObliviousMultiplexer_BFV();
            break;

        case 18:
            numcores = 4;
            GOMR1_FG();
            break;

        case 0:
            return 0;
        }
}
