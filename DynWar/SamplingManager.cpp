/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   SamplingManager.cpp
 * Author: francesco
 * 
 * Created on May 7, 2017, 3:51 PM
 */

#include "SamplingManager.h"

// static
SamplingManager *SamplingManager::s_instance = NULL;

SamplingManager::SamplingManager() {
}

SamplingManager* SamplingManager::getInstance() {
    if (s_instance == NULL) {
        s_instance = new SamplingManager();
    }
    return s_instance;
}

SamplingManager::~SamplingManager() {
}

bool SamplingManager::consider(ip* ip_packet) {
    
    // TODO Decide if flow should be sampled.
    
    return false;
}