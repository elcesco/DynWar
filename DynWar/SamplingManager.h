#pragma once

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   SamplingManager.h
 * Author: francesco
 *
 * Created on May 7, 2017, 3:51 PM
 */

#ifndef SAMPLINGMANAGER_H
#define SAMPLINGMANAGER_H

#include "main.h"

class SamplingManager {
public:
    SamplingManager();
    virtual ~SamplingManager();
    
    static SamplingManager *getInstance();  // get access to the one and only 
                                            // sampling manager instance

    bool consider(const u_char* IPPacket);
    
private:
    static SamplingManager *s_instance; //link to the globally available instance

};

#endif /* SAMPLINGMANAGER_H */

