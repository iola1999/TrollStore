#ifndef PSSPECIFIER_H
#define PSSPECIFIER_H

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, PSCellType) {
	PSGroupCell = 0,
	PSLinkCell = 1,
	PSLinkListCell = 2,
	PSListItemCell = 3,
	PSTitleValueCell = 4,
	PSSliderCell = 5,
	PSSwitchCell = 6,
	PSStaticTextCell = 7,
	PSEditTextCell = 8,
	PSSegmentCell = 9,
	PSGiantIconCell = 10,
	PSGiantCell = 11,
	PSSecureEditTextCell = 12,
	PSButtonCell = 13,
	PSEditTextViewCell = 14,
	PSSpinnerCell = 15,
};

extern NSString *const PSValueKey;
extern NSString *const PSDefaultValueKey;
extern NSString *const PSTableCellKey;

@interface PSSpecifier : NSObject {
@public
	id target;
	SEL getter;
	SEL setter;
	SEL action;
	SEL cancel;
	Class detailControllerClass;
	PSCellType cellType;
	Class editPaneClass;
	NSInteger keyboardType;
	NSInteger autoCapsType;
	NSInteger autoCorrectionType;
	unsigned int textFieldType;
	NSString *_name;
	NSArray *_values;
	NSDictionary *_titleDict;
	NSDictionary *_shortTitleDict;
	id _userInfo;
	NSMutableDictionary *_properties;
}
@property (nonatomic, retain) NSString *name;
@property (nonatomic, retain) NSString *identifier;
@property (nonatomic, retain) id target;
@property (nonatomic, assign) Class detailControllerClass;
@property (nonatomic, assign) PSCellType cellType;
@property (nonatomic, assign) Class editPaneClass;
@property (nonatomic, retain) id userInfo;
@property (nonatomic, retain) NSDictionary *titleDictionary;
@property (nonatomic, retain) NSDictionary *shortTitleDictionary;
@property (nonatomic, assign) SEL buttonAction;
@property (nonatomic, assign) SEL confirmationAction;
@property (nonatomic, assign) SEL confirmationCancelAction;
@property (nonatomic, assign) SEL controllerLoadAction;

+ (instancetype)preferenceSpecifierNamed:(NSString *)identifier target:(id)target set:(SEL)set get:(SEL)get detail:(Class)detail cell:(PSCellType)cell edit:(Class)edit;
+ (instancetype)groupSpecifierWithName:(NSString *)name;
+ (instancetype)groupSpecifierWithID:(NSString *)groupID;
+ (instancetype)groupSpecifierWithID:(NSString *)groupID name:(NSString *)name;
+ (instancetype)emptyGroupSpecifier;

- (id)propertyForKey:(NSString *)key;
- (void)setProperty:(id)property forKey:(NSString *)key;
- (void)removePropertyForKey:(NSString *)key;
- (void)setValues:(NSArray *)values titles:(NSArray *)titles;
- (void)setValues:(NSArray *)values titles:(NSArray *)titles shortTitles:(NSArray *)shortTitles;
@end

#endif
