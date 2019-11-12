
# react-native-hsn-bip39

## Getting started

`$ npm install react-native-hsn-bip39 --save`

### Mostly automatic installation

`$ react-native link react-native-hsn-bip39`

### Manual installation


#### Android

1. Open up `android/app/src/main/java/[...]/MainActivity.java`
  - Add `import com.hsn.bip39.RNBip39Package;` to the imports at the top of the file
  - Add `new RNBip39Package()` to the list returned by the `getPackages()` method
2. Append the following lines to `android/settings.gradle`:
  	```
  	include ':react-native-hsn-bip39'
  	project(':react-native-hsn-bip39').projectDir = new File(rootProject.projectDir, 	'../node_modules/react-native-hsn-bip39/android')
  	```
3. Insert the following lines inside the dependencies block in `android/app/build.gradle`:
  	```
      compile project(':react-native-hsn-bip39')
  	```


## Usage
```javascript
import {NativeModules} from 'react-native-hsn-bip39';
import {RNBip39} from NativeModules;

// TODO: What to do with the module?
RNBip39;
```
  