#import <Foundation/Foundation.h>

BOOL checkDeveloperMode(void)
{
	return YES;
}

BOOL armDeveloperMode(BOOL *alreadyEnabled)
{
	if (alreadyEnabled) {
		*alreadyEnabled = YES;
	}
	return YES;
}
