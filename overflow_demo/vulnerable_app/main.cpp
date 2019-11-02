#include <stdio.h>
#include <string.h>

/** main()的栈帧
 * L  +------+ `.
 *    |      |  |
 *    |      |  | buf[128]
 *    |      |  |
 *    |      |  |
 *    +------+ /
 *    | ebp  |
 *    +------+
 *    |  r   | 返回地址
 * H  +------+
 */

int main()
{
	char buf[128];
	printf("&buf = 0x%.8x\n", buf);
	scanf("%s", buf);
}