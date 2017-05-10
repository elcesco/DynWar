/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Normalizer.h
 * Author: francesco
 *
 * Created on May 10, 2017, 10:22 PM
 */

#ifndef NORMALIZER_H
#define NORMALIZER_H

class NormalizeManager {
public:
    NormalizeManager();
    virtual ~NormalizeManager();
    
    bool clean(const u_char* IPPacket);
    
private:

};

#endif /* NORMALIZER_H */

