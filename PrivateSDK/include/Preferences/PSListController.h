#ifndef PSLISTCONTROLLER_H
#define PSLISTCONTROLLER_H

#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>

@interface PSViewController : UIViewController
@end

@interface PSListController : PSViewController <UITableViewDelegate, UITableViewDataSource> {
@public
	UITableView *_table;
	NSArray *_bundleControllers;
	NSMutableArray *_specifiers;
}
- (NSMutableArray *)specifiers;
- (void)reloadSpecifiers;
- (void)reloadSpecifier:(PSSpecifier *)specifier;
- (void)reloadSpecifier:(PSSpecifier *)specifier animated:(BOOL)animated;
- (void)reloadSpecifierID:(NSString *)identifier;
- (void)reloadSpecifierID:(NSString *)identifier animated:(BOOL)animated;
- (PSSpecifier *)specifierForID:(NSString *)identifier;
- (id)readPreferenceValue:(PSSpecifier *)specifier;
- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier;
- (void)showController:(UIViewController *)controller;
- (void)showController:(UIViewController *)controller animate:(BOOL)animate;
- (NSIndexPath *)indexPathForSpecifier:(PSSpecifier *)specifier;
@end

#endif
