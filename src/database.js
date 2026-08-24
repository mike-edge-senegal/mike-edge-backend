 import React from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { COLORS } from './src/theme';

// ==================== IMPORTATION DES 16 ÉCRANS SCELLÉS ====================
import SplashScreen from './src/screens/SplashScreen';
import LoginScreen from './src/screens/LoginScreen';
import RegisterScreen from './src/screens/RegisterScreen';
import OTPScreen from './src/screens/OTPScreen';
import ForgotPasswordScreen from './src/screens/ForgotPasswordScreen';
import HomeScreen from './src/screens/HomeScreen';
import TicketReaderScreen from './src/screens/TicketReaderScreen';
import EliteScreen from './src/screens/EliteScreen';
import LeaguesScreen from './src/screens/LeaguesScreen';
import EuropeScreen from './src/screens/EuropeScreen';
import WorldScreen from './src/screens/WorldScreen';
import MatchDetailScreen from './src/screens/MatchDetailScreen';
import KioskScreen from './src/screens/KioskScreen';
import MagazineReaderScreen from './src/screens/MagazineReaderScreen';
import ProfileScreen from './src/screens/ProfileScreen';
import SupportScreen from './src/screens/SupportScreen';

const Stack = createNativeStackNavigator();

/**
 * 🏆 APPLICATION PRINCIPALE MIKE EDGE (APP.JS - SCELLÉ V3.5)
 * Navigation Stack complète (16 Écrans / Zéro Stub)
 */
export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer>
        <Stack.Navigator
          initialRouteName="Splash"
          screenOptions={{
            headerShown: false, 
            animation: 'fade',
            contentStyle: { backgroundColor: COLORS.BACKGROUND_DARK },
          }}
        >
          {/* BLOC 1 : ACCÈS & AUTHENTIFICATION */}
          <Stack.Screen name="Splash" component={SplashScreen} />
          <Stack.Screen name="Login" component={LoginScreen} />
          <Stack.Screen name="Register" component={RegisterScreen} />
          <Stack.Screen name="OTP" component={OTPScreen} />
          <Stack.Screen name="ForgotPassword" component={ForgotPasswordScreen} />

          {/* BLOC 2 : ACCUEIL & TICKETS HD */}
          <Stack.Screen name="Home" component={HomeScreen} />
          <Stack.Screen name="TicketReader" component={TicketReaderScreen} />

          {/* BLOC 3 : MATCHS & CLASSEMENTS DYNAMIQUES */}
          <Stack.Screen name="Elite" component={EliteScreen} />
          <Stack.Screen name="Leagues" component={LeaguesScreen} />
          <Stack.Screen name="Europe" component={EuropeScreen} />
          <Stack.Screen name="World" component={WorldScreen} />
          <Stack.Screen name="MatchDetail" component={MatchDetailScreen} />

          {/* BLOC 4 : MAGAZINE HD */}
          <Stack.Screen name="Magazine" component={KioskScreen} />
          <Stack.Screen name="MagazineReader" component={MagazineReaderScreen} />

          {/* BLOC 5 : ABONNÉ & SUPPORT */}
          <Stack.Screen name="Profile" component={ProfileScreen} />
          <Stack.Screen name="Support" component={SupportScreen} />
        </Stack.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}
