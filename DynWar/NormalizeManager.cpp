/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Normalizer.cpp
 * Author: francesco
 * 
 * Created on May 10, 2017, 10:22 PM
 */
#include <cstdio>
#include <sys/types.h>

#include "NormalizeManager.h"

NormalizeManager::NormalizeManager() {
    
    // When the normalizer component is loaded we will load all normalization 
    // techniques and associate each to a specific bit in the vecotr named
    // applyNormalizationTechniques.
    
    
   //TODO: Load normalization techniques.
}

NormalizeManager::~NormalizeManager() {
}

bool NormalizeManager::clean(const u_int64_t * techVector, const u_char* IPPacket) {

    switch (*techVector) {
        case 0: {
            break;
        }
        case 1: {
            break;
        }
        default: {
            std::printf("Unknown identifier for normalization technique");
        }
            
    }
    return true;
}
